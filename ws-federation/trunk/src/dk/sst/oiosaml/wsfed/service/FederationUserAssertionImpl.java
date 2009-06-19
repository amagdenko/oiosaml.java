package dk.sst.oiosaml.wsfed.service;

import java.util.Collections;
import java.util.List;

import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.sst.oiosaml.wsfed.FederationUserAssertion;

public class FederationUserAssertionImpl extends UserAssertionImpl implements FederationUserAssertion {

	public FederationUserAssertionImpl(OIOAssertion assertion) {
		super(assertion);
	}

	@SuppressWarnings("unchecked")
	public List<String> getRoles() {
		UserAttribute a = getAttribute(WSFedConstants.ATTRIBUTE_ROLES);
		if (a == null) return Collections.EMPTY_LIST;
		return a.getValues();
	}

	public String getUserPrincipalName() {
		UserAttribute a = getAttribute(WSFedConstants.ATTRIBUTE_UPN);
		if (a == null) return null;
		
		return a.getValue();
	}

}
