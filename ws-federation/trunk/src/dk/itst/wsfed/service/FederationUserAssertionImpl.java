package dk.itst.wsfed.service;

import java.util.Collections;
import java.util.List;

import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.model.OIOAssertion;

public class FederationUserAssertionImpl extends UserAssertionImpl implements FederationUserAssertion {

	public FederationUserAssertionImpl(OIOAssertion assertion) {
		super(assertion);
	}

	@SuppressWarnings("unchecked")
	public List<String> getRoles() {
		UserAttribute a = getAttribute("http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
		if (a == null) return Collections.EMPTY_LIST;
		return a.getValues();
	}

	public String getUserPrincipalName() {
		UserAttribute a = getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn");
		if (a == null) return null;
		
		return a.getValue();
	}

}
