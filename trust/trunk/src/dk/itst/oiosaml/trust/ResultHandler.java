package dk.itst.oiosaml.trust;

import java.lang.reflect.InvocationTargetException;

import org.opensaml.xml.XMLObject;

public interface ResultHandler {
	
	/**
	 * @param result The body of the result envelope.
	 * @throws Exception If any exception is thrown from a handler, the exception is re-thrown as an {@link InvocationTargetException}.
	 */
	public void handleResult(XMLObject result) throws Exception;

}
