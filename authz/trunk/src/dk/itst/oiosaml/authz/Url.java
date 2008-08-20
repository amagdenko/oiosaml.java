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
