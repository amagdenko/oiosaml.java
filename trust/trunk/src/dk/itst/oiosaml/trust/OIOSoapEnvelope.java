package dk.itst.oiosaml.trust;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.ReplyTo;
import org.opensaml.ws.wsaddressing.To;
import org.opensaml.ws.wssecurity.Created;
import org.opensaml.ws.wssecurity.Expires;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.service.util.Utils;

public class OIOSoapEnvelope {
	private static final Logger log = Logger.getLogger(OIOSoapEnvelope.class);
	
    private Map<AttributeExtensibleXMLObject, String> references = new HashMap<AttributeExtensibleXMLObject, String>();

	private final Envelope envelope;

	private Security security;
	private Body body;
	private XMLSignatureFactory xsf;

	public OIOSoapEnvelope(Envelope envelope) {
		this.envelope = envelope;
		xsf = getXMLSignature();

		for (XMLObject obj : envelope.getHeader().getUnknownXMLObjects()) {
			if (obj instanceof Security) {
				security = (Security)obj;
			}
		}
	}
	
	private OIOSoapEnvelope(Envelope envelope, MessageID msgId, XSAny framework) {
		this(envelope);
		addSignatureElement(msgId);
		addSignatureElement(framework);
	}
	
	public static OIOSoapEnvelope buildEnvelope() {
		Envelope env = SAMLUtil.buildXMLObject(Envelope.class);

		Header header = SAMLUtil.buildXMLObject(Header.class);
		env.setHeader(header);
		
		MessageID msgId = SAMLUtil.buildXMLObject(MessageID.class);
		msgId.setValue(UUID.randomUUID().toString());
		header.getUnknownXMLObjects().add(msgId);
		
		XSAny framework = new XSAnyBuilder().buildObject("urn:liberty:sb:2006-08", "Framework", "sbf");
		framework.getUnknownAttributes().put(new QName("version"), "2.0");
		framework.getUnknownAttributes().put(new QName("urn:liberty:sb:eGov", "profile"), "egovsimple");
		header.getUnknownXMLObjects().add(framework);
		
		Security security = SAMLUtil.buildXMLObject(Security.class);
		security.setMustUnderstand(new XSBooleanValue(true, true));
		header.getUnknownXMLObjects().add(security);
		
		return new OIOSoapEnvelope(env, msgId, framework);
	}
	
	
	public void setBody(OIOIssueRequest request) {
		body = SAMLUtil.buildXMLObject(Body.class);
		body.getUnknownXMLObjects().add(request.getXMLObject());
		addSignatureElement(body);
		
		envelope.setBody(body);
	}
	
	public void setAction(String action) {
		Action a = SAMLUtil.buildXMLObject(Action.class);
		a.setValue(action);
		envelope.getHeader().getUnknownXMLObjects().add(a);
		addSignatureElement(a);
	}
	
	public void addSecurityToken(Assertion token) {
		security.getUnknownXMLObjects().add(token);
	}
	
	public void setTimestamp(int timestampSkew) {
		Timestamp timestamp = SAMLUtil.buildXMLObject(Timestamp.class);
		Created created = SAMLUtil.buildXMLObject(Created.class);
		created.setDateTime(new DateTime().minusMinutes(timestampSkew));
		timestamp.setCreated(created);

		Expires exp = SAMLUtil.buildXMLObject(Expires.class);
		exp.setDateTime(new DateTime().plusMinutes(timestampSkew));
		timestamp.setExpires(exp);
		
		security.getUnknownXMLObjects().add(timestamp);
		addSignatureElement(timestamp);
	}
	
	/**
	 * Sign the SOAP envelope and return the signed DOM element.
	 * 
	 * @param credential Credentials to use for signing.
	 * @return The signed dom element.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws MarshalException
	 * @throws XMLSignatureException
	 */
	public Element sign(X509Credential credential) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		CanonicalizationMethod canonicalizationMethod = xsf.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
		SignatureMethod signatureMethod = xsf.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

		List<Reference> refs = new ArrayList<Reference>();
		
		DigestMethod digestMethod = xsf.newDigestMethod(DigestMethod.SHA1, null);
		List<Transform> transforms = new ArrayList<Transform>(2);
		transforms.add(xsf.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#",new ExcC14NParameterSpec(Collections.singletonList("xsd"))));

		for (Map.Entry<AttributeExtensibleXMLObject, String> ref : references.entrySet()) {
			Reference r = xsf.newReference("#"+ref.getValue(), digestMethod, transforms, null, null);
			refs.add(r);
		}

		// Create the SignedInfo
		SignedInfo signedInfo = xsf.newSignedInfo(canonicalizationMethod, signatureMethod, refs);
		
        KeyInfoFactory keyInfoFactory = xsf.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(credential.getEntityCertificate()));
        KeyInfo ki = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
        
        XMLSignature signature = xsf.newXMLSignature(signedInfo, ki);
        
        String xml = XMLHelper.nodeToString(SAMLUtil.marshallObject(envelope));
        log.debug("Signing envelope: " + xml);
        Element element = SAMLUtil.loadElementFromString(xml);

        Node security = element.getElementsByTagNameNS(WSSecurityConstants.WSSE_NS, "Security").item(0);
        
        DOMSignContext signContext = new DOMSignContext(credential.getPrivateKey(), security); 
        signContext.putNamespacePrefix(SAMLConstants.XMLSIG_NS, SAMLConstants.XMLSIG_PREFIX);
        signContext.putNamespacePrefix(SAMLConstants.XMLENC_NS, SAMLConstants.XMLENC_PREFIX);

        for (AttributeExtensibleXMLObject o : references.keySet()) {
        	NodeList nl = element.getElementsByTagNameNS(o.getDOM().getNamespaceURI(), o.getDOM().getLocalName());
        	for (int i = 0; i < nl.getLength(); i++) {
        		Element e = (Element) nl.item(i);
        		if (e.hasAttributeNS(WSSecurityConstants.WSU_NS, "Id")) {
        			signContext.setIdAttributeNS(e, WSSecurityConstants.WSU_NS, "Id");
        		}
        	}
        }
        
        // Marshal, generate (and sign) the detached XMLSignature. The DOM
        // Document will contain the XML Signature if this method returns
        // successfully.
        // HIERARCHY_REQUEST_ERR: Raised if this node is of a type that does not allow children of the type of the newChild  node, or if the node to insert is one of this node's ancestors.
        signature.sign(signContext);
        return element;
	}
	
	public XMLObject getXMLObject() {
		return envelope;
	}
	
	private XMLSignatureFactory getXMLSignature() {
        // First, create a DOM XMLSignatureFactory that will be used to
        // generate the XMLSignature and marshal it to DOM.
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        try {
			XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());
			return xmlSignatureFactory;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

	private String addSignatureElement(AttributeExtensibleXMLObject obj) {
		String id = Utils.generateUUID();
		obj.getUnknownAttributes().put(TrustConstants.WSU_ID, id);
		
		references.put(obj, id);
		
		return id;
	}

	public void setTo(String endpoint) {
		To to = SAMLUtil.buildXMLObject(To.class);
		to.setValue(endpoint);
		envelope.getHeader().getUnknownXMLObjects().add(to);
		addSignatureElement(to);
	}

	public void setReplyTo(String replyTo) {
		ReplyTo reply = SAMLUtil.buildXMLObject(ReplyTo.class);
		Address addr = SAMLUtil.buildXMLObject(Address.class);
		addr.setValue(replyTo);
		reply.setAddress(addr);
		envelope.getHeader().getUnknownXMLObjects().add(reply);
		addSignatureElement(reply);
	}
	
}
