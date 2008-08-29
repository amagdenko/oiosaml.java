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

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wsaddressing.Metadata;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;

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
		TokenClient client = new TokenClient(epr, credential);
		client.setAppliesTo("urn:appliesto");
		
		String xml = client.toXMLRequest();
		System.out.println(xml);
		
		if (true) return;
		Envelope env = (Envelope) SAMLUtil.unmarshallElementFromString(xml);
		for (XMLObject headerObject : env.getHeader().getOrderedChildren()) {
			if (headerObject == null) continue;
			if (Security.ELEMENT_NAME.equals(headerObject.getElementQName())) {
				Signature signature = (Signature) ((Security)headerObject).getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
				
				BasicX509Credential credential2 = new BasicX509Credential();
				credential2.setPublicKey(credential.getPublicKey());
				SignatureValidator validator = new SignatureValidator(credential);
				validator.validate(signature);
				
				break;
			}
		}


		
		System.out.println(client.request());
	}
}
