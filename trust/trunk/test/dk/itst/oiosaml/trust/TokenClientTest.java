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
package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wsaddressing.Metadata;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.impl.XSAnyUnmarshaller;
import org.opensaml.xml.security.credential.AbstractCredential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.SOAPException;
import dk.itst.oiosaml.sp.service.util.Utils;


public class TokenClientTest extends TrustTests {

	private Assertion assertion;
	private EndpointReference epr;
	private XMLObject request;

	@Before
	public void setUp() throws UnmarshallingException {
		assertion = (Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
		epr = SAMLUtil.buildXMLObject(EndpointReference.class);
		
		Address address = SAMLUtil.buildXMLObject(Address.class);
		address.setValue("http://localhost:8088/TokenService/services/Trust");
		epr.setAddress(address);
		
		Metadata md = SAMLUtil.buildXMLObject(Metadata.class);
		epr.setMetadata(md);

		SecurityContext ctx = SAMLUtil.buildXMLObject(SecurityContext.class);
		md.getUnknownXMLObjects().add(ctx);

		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).setAudienceURI("tri-test1.trifork.com");
		assertion.setSignature(null);
		new OIOAssertion(assertion).sign(Utils.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234"));
		
		Token token = new Token();
		token.setUsage("urn:liberty:security:tokenusage:2006-08:SecurityToken");
		ctx.getTokens().add(token);
		token.setAssertion(assertion);
		
		String echo = "<ns5:echo xmlns:ns5=\"http://provider.poc.saml.itst.dk/\" />";
		
		XSAnyUnmarshaller unmarshaller = new XSAnyUnmarshaller();
		request = unmarshaller.unmarshall(SAMLUtil.loadElementFromString(echo));

}

	@Test
	@Ignore
	public void testRequest() throws Exception {
		BasicX509Credential credential = TestHelper.getCredential();//Utils.getCredential("/home/recht/download/TestMOCES1.pfx", "Test1234");
		BasicX509Credential stsCredential = Utils.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234");
		TrustClient client = new TrustClient(epr, credential, stsCredential.getPublicKey());
		client.setAppliesTo("urn:appliesto");
		
		
		normalRequest(credential, client, request);
		wrongSAMLSignatureShouldFail(credential, client, request);
		signingWithWrongKeyShouldFail(request, stsCredential);
	}

	private void signingWithWrongKeyShouldFail(XMLObject request, AbstractCredential stsCredential) throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		BasicX509Credential credential = TestHelper.getCredential();
		TrustClient client = new TrustClient(epr, credential, stsCredential.getPublicKey());
		client.setAppliesTo("urn:appliesto");
		Assertion token = (Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(client.getToken()));
		
		
		credential = TestHelper.getCredential();
		client = new TrustClient(epr, credential, stsCredential.getPublicKey());
		client.setToken(token);
		try {
			client.sendRequest(request, "http://recht-laptop:8880/poc-provider/ProviderService", "http://provider.poc.saml.itst.dk/Provider/echoRequest");
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertTrue(ex.getFault().getMessage().getValue().toLowerCase().contains("verification"));
			assertTrue(ex.getFault().getMessage().getValue().toLowerCase().contains("failed"));
		}
	}

	/**
	 * Test that only the STS signature is actually accepted.
	 */
	private void wrongSAMLSignatureShouldFail(BasicX509Credential credential, TrustClient client, XMLObject request) throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		Element res = client.getToken();
		Assertion rstrAssertion = (Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(res));
		rstrAssertion.setSignature(null);

		OIOAssertion rstr = new OIOAssertion(rstrAssertion);
		rstr.sign(TestHelper.getCredential());
		
		client.setToken(rstr.getAssertion());
		
		try {
			client.sendRequest(request, "http://recht-laptop:8880/poc-provider/ProviderService", "http://provider.poc.saml.itst.dk/Provider/echoRequest");
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertNotNull(ex.getEnvelope());
			assertNotNull(ex.getFault());
			
			assertTrue(ex.getFault().getMessage().getValue().toLowerCase().contains("validation"));
			assertTrue(ex.getFault().getMessage().getValue().toLowerCase().contains("failed"));
		}
	}

	private void normalRequest(BasicX509Credential credential, TrustClient client, XMLObject request) throws CertificateEncodingException, UnmarshallingException {
		Element res = client.getToken();

		Assertion rstrAssertion = (Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(res));
		OIOAssertion rstr = new OIOAssertion(rstrAssertion);
		
		KeyInfo ki = (KeyInfo) rstrAssertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getUnknownXMLObjects(KeyInfo.DEFAULT_ELEMENT_NAME).get(0);
		X509Certificate cert = ki.getX509Datas().get(0).getX509Certificates().get(0);
		assertNotNull(cert);
		assertTrue(Arrays.equals(credential.getEntityCertificate().getEncoded(), Base64.decode(cert.getValue())));

		assertTrue(rstr.verifySignature(Utils.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234").getPublicKey()));
		
		
		client.setToken(rstrAssertion);
		client.sendRequest(request, "http://recht-laptop:8880/poc-provider/ProviderService", "http://provider.poc.saml.itst.dk/Provider/echoRequest");
	}
}
