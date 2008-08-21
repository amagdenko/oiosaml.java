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
	

	public static final String DENY_PRIVILEGE = "dk:gov:itst:oiosaml:deny";
}
