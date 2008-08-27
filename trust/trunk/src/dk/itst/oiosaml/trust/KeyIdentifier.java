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

import javax.xml.namespace.QName;

import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.util.XMLHelper;

public class KeyIdentifier extends XSAnyImpl {
    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "KeyIdentifier"; 
    public static final QName DEFAULT_ELEMENT_NAME = XMLHelper.constructQName(TrustConstants.WSSE_NS, DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WSSE_PREFIX);

    private static final QName VALUE_TYPE = new QName("ValueType");

	protected KeyIdentifier(String namespaceURI, String elementLocalName, String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
	
	public void setValueType(String valueType) {
		getUnknownAttributes().put(VALUE_TYPE, valueType);
	}
	
	public String getValueType() {
		return getUnknownAttributes().get(VALUE_TYPE);
	}

}
