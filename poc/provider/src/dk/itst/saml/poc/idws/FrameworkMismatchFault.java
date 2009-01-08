package dk.itst.saml.poc.idws;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.soap.SOAPFaultException;

public class FrameworkMismatchFault {

	public static SOAPFaultException createFault(Framework fw) {
		try {
			if (fw == null) {
				return new SOAPFaultException(SOAPFactory.newInstance().createFault("Missing Framework header", new QName("urn:liberty:sb:2006-08", "FrameworkVersionMismatch")));
			} else {
				return new SOAPFaultException(SOAPFactory.newInstance().createFault("Framework version " + fw.getVersion() + " in profile " + fw.getProfile() + " not valid", new QName("urn:liberty:sb:2006-08", "FrameworkVersionMismatch")));
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
		if (!"urn:liberty:sb:profile:basic".equals(fw.getProfile())) {
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
