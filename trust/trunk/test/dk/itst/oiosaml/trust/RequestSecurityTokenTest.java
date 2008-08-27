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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;


public class RequestSecurityTokenTest extends TrustTests {

	@Test
	public void testRequestSecurityToken() {
		RequestSecurityToken token = generateToken();
		
		assertEquals("appliesTo", token.getAppliesTo());
		assertNotNull(token.getOnBehalfOf());
		assertEquals("tokenType", token.getTokenType());
		assertEquals("requestType", token.getRequestType());
	}
	
	@Test
	public void testMarshall() {
		RequestSecurityToken token = generateToken();
		
		Element element = SAMLUtil.marshallObject(token);
		assertEquals("RequestSecurityToken", element.getLocalName());
		assertEquals(TrustConstants.WST_NS, element.getNamespaceURI());
		assertEquals(5, element.getChildNodes().getLength());
	}
	
	@Test
	public void testUnmarshall() {
		RequestSecurityToken token = generateToken();
		String xml = XMLHelper.nodeToString(SAMLUtil.marshallObject(token));
		
		token = (RequestSecurityToken) SAMLUtil.unmarshallElementFromString(xml);
		assertEquals("appliesTo", token.getAppliesTo());
		assertNotNull(token.getOnBehalfOf());
		assertEquals("tokenType", token.getTokenType());
		assertEquals("requestType", token.getRequestType());
		assertEquals("issuer", token.getIssuer());
	}

	private RequestSecurityToken generateToken() {
		RequestSecurityToken token = SAMLUtil.buildXMLObject(RequestSecurityToken.class);
		
		token.setAppliesTo("appliesTo");
		token.setOnBehalfOf(TestHelper.buildAssertion("recp", "aud"));
		token.setTokenType("tokenType");
		token.setRequestType("requestType");
		token.setIssuer("issuer");
		return token;
	}
}
