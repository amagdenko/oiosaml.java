package dk.itst.oiosaml.liberty;

import javax.xml.namespace.QName;

import org.opensaml.ws.wsaddressing.WSAddressingConstants;
import org.opensaml.xml.schema.impl.XSAnyImpl;

public class RelatesTo extends XSAnyImpl {
	public static String LOCAL_NAME = "RelatesTo";
    public final static QName ELEMENT_NAME= new QName(WSAddressingConstants.WSA_NS, LOCAL_NAME, WSAddressingConstants.WSA_PREFIX);

	protected RelatesTo(String namespaceURI, String elementLocalName, String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
}
