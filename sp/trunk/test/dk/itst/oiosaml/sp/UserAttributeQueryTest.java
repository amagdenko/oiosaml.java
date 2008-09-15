/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;

import org.jmock.Expectations;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.BRSConfiguration;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.model.OIOAttributeQuery;
import dk.itst.oiosaml.sp.model.OIOResponse;
import dk.itst.oiosaml.sp.service.AbstractServiceTests;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.SOAPClient;
import dk.itst.oiosaml.sp.util.AttributeUtil;


public class UserAttributeQueryTest extends AbstractServiceTests {
	
	private HashMap<String, String> props;


	@Before
	public void setUp() throws Exception {
		BasicX509Credential cred = TestHelper.getCredential();
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, null);
		X509Certificate cert = TestHelper.getCertificate(cred);
		cred.setEntityCertificate(cert);
		
		ks.setKeyEntry("oiosaml", credential.getPrivateKey(), "password".toCharArray(), new Certificate[] { cert });
		
		File tmp = File.createTempFile("test", "test");
		tmp.deleteOnExit();
		FileOutputStream os = new FileOutputStream(tmp);
		ks.store(os, "password".toCharArray());
		os.close();

		props = new HashMap<String, String>();
		props.put(SAMLUtil.OIOSAML_HOME, System.getProperty("java.io.tmpdir"));
		props.put(Constants.PROP_CERTIFICATE_LOCATION, tmp.getName());
		props.put(Constants.PROP_CERTIFICATE_PASSWORD, "password");
		
		BRSConfiguration.setSystemConfiguration(TestHelper.buildConfiguration(props));
		IdpMetadata.setMetadata(new IdpMetadata(TestHelper.buildEntityDescriptor(cred)));
		SPMetadata.setMetadata(spMetadata);
	}
	
	@After
	public void tearDown() {
		IdpMetadata.setMetadata(null);
		SPMetadata.setMetadata(null);
	}

	@Test(expected=IllegalArgumentException.class)
	public void testDefaultFailOnNoAssertion() throws Exception {
		UserAssertionHolder.set(null);
		new UserAttributeQuery();
	}
	

	@Test
	public void testDefault() throws Exception {
		final UserAssertion ua = context.mock(UserAssertion.class);
		context.checking(new Expectations() {{
			one(ua).getIssuer(); will(returnValue(idpEntityId));
		}});
		UserAssertionHolder.set(ua);
		new UserAttributeQuery();
	}
	
	@Test
	public void testQuery() throws Exception{
		final SOAPClient client = context.mock(SOAPClient.class);
		final String location = idpMetadata.getFirstMetadata().getAttributeQueryServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		
		Assertion ass = TestHelper.buildAssertion(null, spMetadata.getEntityID());
		ass.getAttributeStatements().get(0).getAttributes().clear();
		AttributeStatement stmt = SAMLUtil.buildXMLObject(AttributeStatement.class);
		stmt.getAttributes().add(AttributeUtil.createAttribute("attr1", null, null));
		stmt.getAttributes().add(AttributeUtil.createAttribute("attr2", null, null));
		ass.getAttributeStatements().add(stmt);
		
		final Response resp = SAMLUtil.buildXMLObject(Response.class);
		resp.getAssertions().add(ass);
		resp.setIssuer(SAMLUtil.createIssuer(idpEntityId));
		resp.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		new OIOResponse(resp).sign(credential);
		
		context.checking(new Expectations() {{
			one(client).wsCall(with(any(OIOAttributeQuery.class)), with(any(LogUtil.class)), with(equal(location)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)));
			will(returnValue(resp));
		}});
		
		UserAttributeQuery q = new UserAttributeQuery(idpMetadata.getFirstMetadata(), null, null, client, credential, true, false, spMetadata.getEntityID());
		Collection<UserAttribute> attrs = q.query("name", NameIDFormat.EMAIL,"attr1", "attr2");
		assertEquals(2, attrs.size());
	}
}
