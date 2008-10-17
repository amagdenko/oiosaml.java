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

import org.opensaml.ws.wssecurity.WSSecurityConstants;

public class TrustConstants {

	public static final String SAMLID = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID";
	public static final String TOKEN_TYPE_SAML_20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
	
	public static final String WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";
	public static final String WST_PREFIX = "wst";
	public static final String WSSE11_NS = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
	public static final String WSSE11_PREFIX = "wsse11";
	
	public static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	public static final String WSSE_PREFIX = "wsse";
	
	public static final String WSP_NS = "http://schemas.xmlsoap.org/ws/2002/12/policy";
	public static final String WSP_PREFIX = "wsp";

	public static final QName WSU_ID = new QName(WSSecurityConstants.WSU_NS, "Id", WSSecurityConstants.WSU_PREFIX);
	
	public static final String PROP_CERTIFICATE_LOCATION = "oiosaml-trust.certificate.location";
	public static final String PROP_CERTIFICATE_PASSWORD = "oiosaml-trust.certificate.password";	
	public static final String PROP_CERTIFICATE_ALIAS = "oiosaml-trust.certificate.alias";
}
