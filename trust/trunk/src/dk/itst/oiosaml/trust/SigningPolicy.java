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
 * The Original Code is OIOSAML Trust Client.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
package dk.itst.oiosaml.trust;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.opensaml.xml.XMLObject;

/**
 * Policy class describing which elements should be signed in a soap request.
 * 
 * This class is primarily used by {@link OIOSoapEnvelope}.
 *
 */
public class SigningPolicy {
	private static final Logger log = Logger.getLogger(SigningPolicy.class);
	
	private Map<QName, Boolean> policies = new ConcurrentHashMap<QName, Boolean>();
	private boolean defaultPolicy = false;

	/**
	 * Create a new policy.
	 * @param signByDefault The default signing policy. <code>true</code> signs all elements, unless a specific policy has been added.
	 */
	public SigningPolicy(boolean signByDefault) {
		defaultPolicy = signByDefault;
	}

	/**
	 * Add a specific policy.
	 * @param type The element type to control.
	 * @param sign Whether to sign the element or not.
	 */
	public void addPolicy(QName type, boolean sign) {
		policies.put(type, sign);
	}
	
	public boolean sign(QName type) {
		Boolean sign = policies.get(type);
		if (sign == null) {
			sign = defaultPolicy;
		}
		log.debug("Sign " + type + ": " + sign);
		return sign;
	}
	
	public boolean sign(XMLObject element) {
		return sign(element.getElementQName());
	}
	
	public boolean isSigningDefault() {
		return defaultPolicy;
	}
}
