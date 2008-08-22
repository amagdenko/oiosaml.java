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

import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.UserAttribute;

/**
 * Main application entry point for oiosaml-authz.
 * 
 * <p>Use this class to checks authorisations programatically. On a live system, use {@link #getDefault()} to get a configured object and call
 * {@link #hasAccess(String, String, String, UserAssertion)} to check if a user has access to a given resource.</p>
 * 
 * @author recht
 *
 */
public class Authz {
	private static final Authorisations NO_AUTHS = new Authorisations("<Authorisations xmlns=\"http://www.eogs.dk/2007/07/brs\"></Authorisations>");

	private static Protections globalprotections;

	private final Protections protections;

	public Authz(Protections protections) {
		this.protections = protections;
	}

	public boolean hasAccess(String resource, String url, String method, UserAssertion userAssertion) {
		if (userAssertion == null) return false;
		
		UserAttribute auths = userAssertion.getAttribute(Constants.AUTHORISATIONS_ATTRIBUTE);
		Authorisations authorisations;
		if (auths == null) {
			authorisations = NO_AUTHS;
		} else {
			authorisations = new Authorisations(auths.getValue());
		}
		return protections.isAuthorised(resource, url, method, authorisations);
	}

	/**
	 * Check access based on a String representation of an brs:Authorisations structure.
	 * 
	 * @param resource Requested resource.
	 * @param url Requested url.
	 * @param method HTTP method used.
	 * @param authorisations User authorisations as a string.
	 * @return <code>true</code> if access can be granted, <code>false</code> otherwise.
	 */
	public boolean hasAccess(String resource, String url, String method, String authorisations) {
		Utils.checkNotNull(authorisations, "authorisations");
		return protections.isAuthorised(resource, url, method, new Authorisations(authorisations));
	}
	
	/**
	 * Set the protections used by {@link #getDefault()}. Generally, this method should only be used when testing.
	 * 
	 * @param protections
	 */
	public static void setProtections(Protections protections) {
		Authz.globalprotections = protections;
	}
	
	public static Authz getDefault() {
		if (globalprotections == null) {
			throw new IllegalStateException("Authz has not been configured. Make sure AuthzFilter is loaded");
		}
		return new Authz(globalprotections);
	}
}
