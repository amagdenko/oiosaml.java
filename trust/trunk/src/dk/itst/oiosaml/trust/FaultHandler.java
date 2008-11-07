package dk.itst.oiosaml.trust;

import javax.xml.namespace.QName;

import org.opensaml.xml.XMLObject;

/**
 * Handle SOAP Faults.
 *
 */
public interface FaultHandler {

	/**
	 * Invoked when a SOAP fault occurs.
	 * @param faultCode The FaultCode.
	 * @param faultMessage Fault Message.
	 * @param detail The Fault detail element.
	 */
	public void handleFault(QName faultCode, String faultMessage, XMLObject detail);
}
