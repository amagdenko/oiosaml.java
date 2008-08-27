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

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;


public class KeyIdentifierTest extends TrustTests {
	
	private KeyIdentifier ki;

	@Before
	public void setUp() {
		ki = generateIdentifier();
	}
	
	@Test
	public void testGet() throws Exception {
		assertEquals("type", ki.getValueType());
		assertEquals("text", ki.getTextContent());
	}

	@Test
	public void testMarshall() throws Exception {
		Element e = SAMLUtil.marshallObject(ki);
		assertEquals("KeyIdentifier", e.getLocalName());
		assertEquals(TrustConstants.WSSE_NS, e.getNamespaceURI());
		assertEquals("text", e.getTextContent());
	}
	
	@Test
	public void testUnmarshall() {
		String xml = "<KeyIdentifier xmlns=\"" + TrustConstants.WSSE_NS + "\" ValueType=\"type\">text</KeyIdentifier>";
		KeyIdentifier ki = (KeyIdentifier) SAMLUtil.unmarshallElementFromString(xml);
		assertEquals("type", ki.getValueType());
		assertEquals("text", ki.getTextContent());
	}

	private KeyIdentifier generateIdentifier() {
		KeyIdentifier ki = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		ki.setValueType("type");
		ki.setTextContent("text");
		return ki;
	}
}
