package dk.itst.oiosaml.trust.internal;

import java.security.InvalidAlgorithmParameterException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.log4j.Logger;
import org.jcp.xml.dsig.internal.dom.ApacheTransform;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class DOMSTRTransform  extends ApacheTransform {
	private static final Logger log = Logger.getLogger(DOMSTRTransform.class);
	
	@Override
	public void init(TransformParameterSpec params) throws InvalidAlgorithmParameterException {
		log.debug("INIT: " + params);
		
		this.params = params;
	}

	public void init(XMLStructure parent, XMLCryptoContext context) throws InvalidAlgorithmParameterException {

		super.init(parent, context);
		log.debug("INIT2: " + transformElem);
		
		DOMStructure str = (DOMStructure) parent;
		str.getNode();
		
		this.params = new ExcC14NParameterSpec();
		
	}
	
	@Override
	public void marshalParams(XMLStructure parent, XMLCryptoContext context) throws MarshalException {
		super.marshalParams(parent, context);
		
		Node node = ((DOMStructure) parent).getNode();
		Document doc = node.getOwnerDocument();
		Element tp = XMLHelper.constructElement(doc, WSSecurityConstants.WSSE_NS, "TransformationParameters", WSSecurityConstants.WSSE_PREFIX);
		Element cm = XMLHelper.constructElement(doc, XMLSignature.XMLNS, "CanonicalizationMethod", "ds");
		tp.appendChild(cm);
		cm.setAttributeNS(null, "Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
		node.appendChild(tp);
		
		log.debug("Marshall: " + XMLHelper.nodeToString(node));
	}
}
