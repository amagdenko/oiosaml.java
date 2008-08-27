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

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;

public class SecurityTokenReference extends TrustObject {
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "SecurityTokenReference"; 
    public static final QName DEFAULT_ELEMENT_NAME = XMLHelper.constructQName(TrustConstants.WSSE_NS, DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WSSE_PREFIX);

    private static final QName TOKEN_TYPE = new QName(TrustConstants.WSSE11_NS, "TokenType", TrustConstants.WSSE11_PREFIX);

    private KeyIdentifier keyIdentifier;
    
	protected SecurityTokenReference(String namespaceURI, String elementLocalName, String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}

	public String getTokenType() {
		return otherAttributes.get(TOKEN_TYPE);
	}

	public void setTokenType(String tokenType) {
		otherAttributes.put(TOKEN_TYPE, tokenType);
	}

	public KeyIdentifier getKeyIdentifier() {
		return keyIdentifier;
	}

	public void setKeyIdentifier(KeyIdentifier keyIdentifier) {
		this.keyIdentifier = keyIdentifier;
	}
	
	@Override
	protected List<XMLObject> buildOrderedChildren() {
		List<XMLObject> res = new ArrayList<XMLObject>();
		if (keyIdentifier != null) {
			res.add(keyIdentifier);
		}
		return res;
	}
}
