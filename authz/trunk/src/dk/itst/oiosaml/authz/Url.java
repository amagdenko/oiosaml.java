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

import java.util.Collection;

import org.apache.log4j.Logger;

/**
 * Representation of the Url XML structure. 
 * 
 * @author recht
 *
 */
public class Url {
	private static final Logger log = Logger.getLogger(Url.class);

	private final String path;
	private final String method;
	private final Collection<String> privileges;

	/**
	 * 
	 * @param path Regexp describing the paths matched by this object.
	 * @param method Http method matched by this object. If <code>null</code> or '*' it will match all methods.
	 * @param privileges Privileges defined for this url.
	 */
	public Url(String path, String method, Collection<String> privileges) {
		Utils.checkNotNull(path, "path");
		Utils.checkNotNull(privileges, "privileges");
		
		this.path = path;
		if (method == null || (method != null && "".equals(method.trim()))) {
			method = "*";
		}
		this.method = method;
		this.privileges = privileges;
	}

	/**
	 * Check if this url object matches the input arguments.
	 * 
	 * @param url Url to match against.
	 * @param method Http method from the request.
	 */
	public boolean matches(String url, String method) {
		Utils.checkNotNull(url, "url");
		
		if (!(this.method.equalsIgnoreCase(method) || "*".equals(this.method))) {
			if (log.isDebugEnabled()) log.debug("Url " + this + " does not match. Input method is " + method);
			return false;
		}
		
		boolean res = url.matches(path);
		if (log.isDebugEnabled()) log.debug("Url '" + url + "' matches '" + path + "': " + res);
		return res;
	}
	
	public Collection<String> getPrivileges() {
		return privileges;
	}
	
	@Override
	public String toString() {
		return "Url[path=" + path + ", method=" + method + "]";
	}
}
