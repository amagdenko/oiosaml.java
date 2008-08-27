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
import org.openliberty.xmltooling.Konstantz;
import org.openliberty.xmltooling.disco.SecurityContext;
import org.openliberty.xmltooling.disco.SecurityContextBuilder;
import org.openliberty.xmltooling.security.Token;
import org.openliberty.xmltooling.wsa.Address;
import org.openliberty.xmltooling.wsa.EndpointReference;
import org.openliberty.xmltooling.wsa.Metadata;
import org.openliberty.xmltooling.wsse.Security;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Utils;


public class TokenClientTest extends AbstractTests {

	private Assertion assertion;

	@Before
	public void setUp() {
		assertion = (Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
	}

	@Test
	@Ignore
	public void testRequest() throws Exception {
		EndpointReference epr = new EndpointReference();
		
		Address address = new Address();
//		address.setValue("http://localhost:8880/sts/TokenServiceService");
//		address.setValue("http://tri-test1.trifork.com:8080/sts/");
		address.setValue("http://localhost:8088/TokenService/services/Trust");
		epr.setAddress(address);
		
		Metadata md = new Metadata();
		epr.setMetadata(md);
		

		
		SecurityContext ctx = new SecurityContextBuilder().buildObject(Konstantz.DS_NS, SecurityContext.LOCAL_NAME, Konstantz.DS_PREFIX);
		md.getSecurityContexts().add(ctx);

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
		Envelope env = (Envelope) SAMLUtil.unmarshallElementFromString(xml);
		for (XMLObject headerObject : env.getHeader().getOrderedChildren()) {
			if (headerObject == null) continue;
			if (Security.DEFAULT_ELEMENT_NAME.equals(headerObject.getElementQName())) {
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
