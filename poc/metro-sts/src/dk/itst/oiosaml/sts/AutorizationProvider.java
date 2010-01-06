package dk.itst.oiosaml.sts;

import javax.security.auth.Subject;

import com.sun.xml.ws.api.security.trust.STSAuthorizationProvider;

public class AutorizationProvider implements STSAuthorizationProvider {

	public boolean isAuthorized(Subject subject, String appliesTo, String tokenType, String keyType) {
		return true;
	}
}
