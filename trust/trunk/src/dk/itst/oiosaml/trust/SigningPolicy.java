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
