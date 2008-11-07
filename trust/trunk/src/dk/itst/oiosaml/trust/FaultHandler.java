package dk.itst.oiosaml.trust;

import java.lang.reflect.InvocationTargetException;

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
	 * @throws Exception If any exception is thrown from a handler, the exception is re-thrown as an {@link InvocationTargetException}.
	 */
	public void handleFault(QName faultCode, String faultMessage, XMLObject detail) throws Exception;
}
