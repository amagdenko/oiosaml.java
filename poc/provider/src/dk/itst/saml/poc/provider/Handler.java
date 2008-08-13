package dk.itst.saml.poc.provider;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.opensaml.xml.util.XMLHelper;

public class Handler implements SOAPHandler<SOAPMessageContext> {

	public Handler() {
		System.out.println("Handler.Hander()");
	}
	public Set<QName> getHeaders() {
		return null;
	}

	public void close(MessageContext arg0) {
	}

	public boolean handleFault(SOAPMessageContext arg0) {
		return true;
	}

	public boolean handleMessage(SOAPMessageContext ctx) {
		if ((Boolean)ctx.get("javax.xml.ws.handler.message.outbound")) return true;
		ctx.put("envelope", XMLHelper.nodeToString(ctx.getMessage().getSOAPPart().getDocumentElement()));
		System.out.println(ctx.get("envelope"));
		
		return true;
	}
}
