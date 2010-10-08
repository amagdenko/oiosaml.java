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
package dk.itst.oiosaml.sp;

import java.security.Principal;

public class OIOPrincipal implements Principal {
	
	private final UserAssertion assertion;

	public OIOPrincipal(UserAssertion assertion) {
		this.assertion = assertion;
	}

	public String getName() {
		return assertion.getSubject();
	}

	public UserAssertion getAssertion() {
		return assertion;
	}
	
	public String toString() {
		return "SAML Assertion subject: " + assertion.getSubject() + " - assurance level : " + assertion.getAssuranceLevel();
	}
}
