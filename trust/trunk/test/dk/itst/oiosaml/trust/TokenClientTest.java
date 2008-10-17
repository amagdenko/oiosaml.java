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

import java.util.Arrays;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wsaddressing.Metadata;
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
import dk.itst.oiosaml.sp.service.util.Utils;


public class TokenClientTest extends TrustTests {

	private Assertion assertion;

	@Before
	public void setUp() {
		assertion = (Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
	}

	@Test
	@Ignore
	public void testRequest() throws Exception {
		EndpointReference epr = SAMLUtil.buildXMLObject(EndpointReference.class);
		
		Address address = SAMLUtil.buildXMLObject(Address.class);
//		address.setValue("http://localhost:8880/sts/TokenServiceService");
//		address.setValue("http://tri-test1.trifork.com:8080/sts/");
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
		
		
		BasicX509Credential credential = Utils.getCredential("/home/recht/download/TestMOCES1.pfx", "Test1234");
		BasicX509Credential stsCredential = Utils.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234");
		TokenClient client = new TokenClient(epr, credential, stsCredential.getPublicKey());
		client.setAppliesTo("urn:appliesto");
		
//		String xml = client.toXMLRequest();
//		System.out.println(xml);
//		
//		if (true) return;
//		Envelope env = (Envelope) SAMLUtil.unmarshallElementFromString(xml);
//		for (XMLObject headerObject : env.getHeader().getOrderedChildren()) {
//			if (headerObject == null) continue;
//			if (Security.ELEMENT_NAME.equals(headerObject.getElementQName())) {
//				Signature signature = (Signature) ((Security)headerObject).getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
//				
//				BasicX509Credential credential2 = new BasicX509Credential();
//				credential2.setPublicKey(credential.getPublicKey());
//				SignatureValidator validator = new SignatureValidator(credential);
//				validator.validate(signature);
//				
//				break;
//			}
//		}
//

		
		Element res = client.getToken();
		
		System.out.println(res);
		
		Assertion rstrAssertion = (Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(res));
		OIOAssertion rstr = new OIOAssertion(rstrAssertion);
		
		KeyInfo ki = (KeyInfo) rstrAssertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getUnknownXMLObjects(KeyInfo.DEFAULT_ELEMENT_NAME).get(0);
		X509Certificate cert = ki.getX509Datas().get(0).getX509Certificates().get(0);
		assertNotNull(cert);
		assertTrue(Arrays.equals(credential.getEntityCertificate().getEncoded(), Base64.decode(cert.getValue())));
		
		assertTrue(rstr.verifySignature(Utils.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234").getPublicKey()));
	}
}
