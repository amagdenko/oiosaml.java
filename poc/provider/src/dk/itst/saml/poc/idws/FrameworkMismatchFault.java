package dk.itst.saml.poc.idws;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.soap.SOAPFaultException;

public class FrameworkMismatchFault extends SOAPFaultException {

	public FrameworkMismatchFault(String version, String profile) throws SOAPException {
		super(SOAPFactory.newInstance().
				createFault("Framework version " + version + " in profile " + profile + " not valid", new QName("urn:liberty:sb:2006-08", "FrameworkVersionMismatch")));
	}
	
	public static FrameworkMismatchFault createFault(Framework fw) {
		try {
			if (fw == null) {
				return new FrameworkMismatchFault(null, null);
			} else {
				return new FrameworkMismatchFault(fw.getVersion(), fw.getProfile());
			}
		} catch (SOAPException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void throwIfNecessary(Framework fw, MessageContext messageContext) {
		if (fw == null) {
			setError(messageContext);
			throw createFault(fw);
		}
		if (!"egovsimple".equals(fw.getProfile())) {
			setError(messageContext);
			throw createFault(fw);
		}
		if (!"2.0".equals(fw.getVersion())) {
			setError(messageContext);
			throw createFault(fw);
		}
	}
	
	private static void setError(MessageContext ctx) {
		ctx.put(MessageContext.HTTP_RESPONSE_CODE, 500);
	}

}
