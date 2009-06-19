package dk.sst.oiosaml.wsfed.service;

public class WSFedConstants {
	private WSFedConstants() {}
	
	public static final String PROP_USE_REDIRECT = "oiosaml-wsfed.useredirect";
	public static final String WSFED_PROTOCOL = "http://schemas.xmlsoap.org/ws/2006/12/federation";
	public static final String WSFED_SIGNIN = "wsignin1.0";
	public static final String WSFED_SIGNOUT = "wsignout1.0";
	
	public static final String ATTRIBUTE_ROLES = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
	public static final String ATTRIBUTE_UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
}
