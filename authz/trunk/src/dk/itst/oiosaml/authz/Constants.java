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
 * The Original Code is OIOSAML Authz
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
package dk.itst.oiosaml.authz;

public final class Constants {

	private Constants() {}
	
	public static final String AUTHORISATIONS_ATTRIBUTE = "dk:gov:virk:saml:attribute:Authorisations";
	public static final String PRODUCTION_CODE_ATTRIBUTE = "dk:gov:virk:saml:attribute:ProductionUnitIdentifier";
	
	public static final String RESOURCE_CVR_NUMBER_PREFIX ="urn:dk:cvr:cVRnumberIdentifier:";
	public static final String RESOURCE_PNUMER_PREFIX = "urn:dk:cvr:productionUnitIdentifier:";
	
	public static final String BRS_NS = "http://www.eogs.dk/2007/07/brs";
	public static final String ELEMENT_AUTHORISATIONS = "Authorisations";
	public static final String ELEMENT_AUTHORISATION = "Authorisation";
	public static final String ELEMENT_PRIVILEGE = "Privilege";
	public static final String ATTRIBUTE_RESOURCE = "resource";
	
	public static final String PROP_PROTECTION_CONFIG_FILE = "oiosaml.authz.config";
	public static final String PROP_PROTECTION_ERROR_SERVLET = "oiosaml.authz.servlet";
	public static final String PROP_ATTRIBUTE_QUERY = "oiosaml.authz.attributequery";
	
	public static final String SESSION_AUTHORISATIONS = "dk:gov:virk:saml:attribute:Authorisations";
	

	public static final String DENY_PRIVILEGE = "dk:gov:itst:oiosaml:deny";
}
