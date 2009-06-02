package dk.itst.wsfed.service;

import java.util.List;

import dk.itst.oiosaml.sp.UserAssertion;

public interface FederationUserAssertion extends UserAssertion {

	public String getUserPrincipalName();
	
	public List<String> getRoles();
}
