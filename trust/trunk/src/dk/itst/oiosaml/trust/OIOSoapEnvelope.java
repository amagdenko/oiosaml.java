package dk.itst.oiosaml.trust;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
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
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
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
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.trust.internal.DOMSTRTransform;
import dk.itst.oiosaml.trust.internal.STRTransform;

public class OIOSoapEnvelope {
	private static final Logger log = Logger.getLogger(OIOSoapEnvelope.class);
	
	static {
		try {
			org.apache.xml.security.transforms.Transform.register(STRTransform.implementedTransformURI, STRTransform.class.getName());
			log.debug("STR-Transform registered");
		} catch (AlgorithmAlreadyRegisteredException e) {
			log.info("STR-Transform already registered", e);
		}

	}
	
    private Map<XMLObject, String> references = new HashMap<XMLObject, String>();

	private final Envelope envelope;

	private Security security;
	private Body body;
	private XMLSignatureFactory xsf;
	
	private Assertion securityToken;

	private SecurityTokenReference securityTokenReference;

	public OIOSoapEnvelope(Envelope envelope) {
		if (envelope == null) throw new IllegalArgumentException("Envelope cannot be null");
		
		this.envelope = envelope;
		xsf = getXMLSignature();

		security = SAMLUtil.getFirstElement(envelope.getHeader(), Security.class);
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
	
	
	public void setBody(XMLObject request) {
		body = SAMLUtil.buildXMLObject(Body.class);
		body.getUnknownXMLObjects().add(request);
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
	
	public void addSecurityTokenReference(Assertion token) {
		if (token == null) return;
		
		token.detach();
		securityToken = token;
		addSecurityToken(token);
		
		SecurityTokenReference str = createSecurityTokenReference(token);
		security.getUnknownXMLObjects().add(str);
	}

	private SecurityTokenReference createSecurityTokenReference(Assertion token) {
		SecurityTokenReference str = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		str.setTokenType(WSSecurityConstants.WSSE11_SAML_TOKEN_PROFILE_NS + "#SAMLV2.0");
		str.setId(Utils.generateUUID());
		
		KeyIdentifier keyIdentifier = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		keyIdentifier.setValueType(WSSecurityConstants.WSSE11_SAML_TOKEN_PROFILE_NS + "#SAMLID");
		keyIdentifier.setValue(token.getID());
		str.setKeyIdentifier(keyIdentifier);
		
		return str;
	}
	
	public boolean relatesTo(String messageId) {
		if (envelope.getHeader() == null) return false;
		List<XMLObject> objects = envelope.getHeader().getUnknownXMLObjects(TrustConstants.WSA_RELATES_TO);
		if (objects.isEmpty()) return false;
		
		XMLObject object = objects.get(0);
		String relatesTo;
		if (object instanceof XSAny) {
			relatesTo = ((XSAny)object).getTextContent();
		} else {
			Element e = SAMLUtil.marshallObject(object);
			relatesTo = e.getTextContent().trim();
		}
		return messageId.equals(relatesTo);
	}
	
	public void setTimestamp(int timestampSkew) {
		DateTime now = new DateTime().toDateTime(DateTimeZone.UTC);
		
		Timestamp timestamp = SAMLUtil.buildXMLObject(Timestamp.class);
		Created created = SAMLUtil.buildXMLObject(Created.class);
		created.setDateTime(now.minusMinutes(timestampSkew));
		timestamp.setCreated(created);

		Expires exp = SAMLUtil.buildXMLObject(Expires.class);
		exp.setDateTime(now.plusMinutes(timestampSkew));
		timestamp.setExpires(exp);
		
		security.getUnknownXMLObjects().add(timestamp);
		addSignatureElement(timestamp);
	}
	
	/**
	 * Get the first element of the envelope body.
	 */
	public XMLObject getBody() {
		return envelope.getBody().getUnknownXMLObjects().get(0);
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

		for (Map.Entry<XMLObject, String> ref : references.entrySet()) {
			Reference r = xsf.newReference("#"+ref.getValue(), digestMethod, transforms, null, null);
			refs.add(r);
		}
		
		SAMLUtil.marshallObject(envelope);
		
		if (securityTokenReference != null) {
			transforms = new ArrayList<Transform>();
			
			Document doc = envelope.getDOM().getOwnerDocument();
			Element tp = XMLHelper.constructElement(doc, WSSecurityConstants.WSSE_NS, "TransformationParameters", WSSecurityConstants.WSSE_PREFIX);
			Element cm = XMLHelper.constructElement(doc, XMLSignature.XMLNS, "CanonicalizationMethod", "ds");
			tp.appendChild(cm);
			cm.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
			
			
			transforms.add(getSpecial().newTransform("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform",  new DOMStructure(tp)));
			Reference r = xsf.newReference("#"+securityTokenReference.getId(), digestMethod, transforms, null, null);
			refs.add(r);
		}

		// Create the SignedInfo
		SignedInfo signedInfo = xsf.newSignedInfo(canonicalizationMethod, signatureMethod, refs);
		
        KeyInfoFactory keyInfoFactory = xsf.getKeyInfoFactory();
        KeyInfo ki;
        if (isHolderOfKey()) {
        	DOMStructure info = new DOMStructure(SAMLUtil.marshallObject(createSecurityTokenReference(securityToken)));
        	ki = keyInfoFactory.newKeyInfo(Collections.singletonList(info));
        } else {
        	X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(credential.getEntityCertificate()));
        	ki = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
        }
        
        
        XMLSignature signature = xsf.newXMLSignature(signedInfo, ki);
        
        String xml = XMLHelper.nodeToString(envelope.getDOM());
        log.debug("Signing envelope: " + xml);
        Element element = SAMLUtil.loadElementFromString(xml);
        
        Node security = element.getElementsByTagNameNS(WSSecurityConstants.WSSE_NS, "Security").item(0);
        
        DOMSignContext signContext = new DOMSignContext(credential.getPrivateKey(), security); 
        signContext.putNamespacePrefix(SAMLConstants.XMLSIG_NS, SAMLConstants.XMLSIG_PREFIX);
        signContext.putNamespacePrefix(SAMLConstants.XMLENC_NS, SAMLConstants.XMLENC_PREFIX);

        for (XMLObject o : references.keySet()) {
        	NodeList nl = element.getElementsByTagNameNS(o.getDOM().getNamespaceURI(), o.getDOM().getLocalName());
        	for (int i = 0; i < nl.getLength(); i++) {
        		Element e = (Element) nl.item(i);
        		if (e.hasAttributeNS(WSSecurityConstants.WSU_NS, "Id")) {
        			signContext.setIdAttributeNS(e, WSSecurityConstants.WSU_NS, "Id");
        			e.setIdAttributeNS(WSSecurityConstants.WSU_NS, "Id", true);
        		}
        	}
        }
        if (securityTokenReference != null) {
        	NodeList nl = element.getElementsByTagNameNS(SecurityTokenReference.ELEMENT_NAME.getNamespaceURI(), SecurityTokenReference.ELEMENT_LOCAL_NAME);
        	for (int i = 0; i < nl.getLength(); i++) {
        		Element e = (Element) nl.item(i);
        		e.setIdAttributeNS(WSSecurityConstants.WSU_NS, "Id", true);
        	}
        	nl = element.getElementsByTagNameNS(securityToken.getElementQName().getNamespaceURI(), securityToken.getElementQName().getLocalPart());
        	for (int i = 0; i < nl.getLength(); i++) {
        		Element e = (Element) nl.item(i);
        		if (e.hasAttribute("ID")) {
        			e.setIdAttributeNS(null, "ID", true);
        		}
        		if (e.hasAttributeNS(WSSecurityConstants.WSU_NS, "Id")) {
        			e.setIdAttributeNS(WSSecurityConstants.WSU_NS, "Id", true);
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
	
	public boolean isSigned() {
		boolean signed = SAMLUtil.getFirstElement(security, Signature.class) != null;
		log.debug("Envelope signed: " + signed);
		return signed;
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

	/**
	 * Get an XML representation of the object.
	 */
	public String toXML() {
		Element e = SAMLUtil.marshallObject(envelope);
		return XMLHelper.nodeToString(e);
	}
	
	public <T extends XMLObject> T getHeaderElement(Class<T> type) {
		return SAMLUtil.getFirstElement(envelope.getHeader(), type);
	}
	
	public boolean verifySignature(PublicKey key) {
		if (!isSigned()) return false; 
		return new OIOSamlObject(security).verifySignature(key);
	}


	
	public boolean isHolderOfKey() {
		if (securityToken == null) return false;
		if (securityToken.getSubject() == null) return false;
		if (securityToken.getSubject().getSubjectConfirmations().isEmpty()) return false;
		
		return TrustConstants.CONFIRMATION_METHOD_HOK.equals(securityToken.getSubject().getSubjectConfirmations().get(0).getMethod());
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

	@SuppressWarnings("unchecked")
	private XMLSignatureFactory getSpecial() {
		Provider p = new Provider("XMLStr", 1.0, "INFO") {
			{
			final Map map = new HashMap();
			
			map.put("XMLSignatureFactory.DOM", "org.jcp.xml.dsig.internal.dom.DOMXMLSignatureFactory");
			
			map.put("TransformService." + STRTransform.implementedTransformURI, DOMSTRTransform.class.getName());
			map.put("Alg.Alias.TransformService.STRTRANSFORM", STRTransform.implementedTransformURI);
			map.put("TransformService." + STRTransform.implementedTransformURI + " MechanismType", "DOM");
			
			putAll(map);
			}
		};
        try {
			XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", p);
			return xmlSignatureFactory;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}	
	
    public static class STRTransformParameterSpec implements TransformParameterSpec {
        private CanonicalizationMethod c14nMethod;
        public STRTransformParameterSpec(CanonicalizationMethod c14nMethod) {
            this.c14nMethod = c14nMethod;
        }
        public CanonicalizationMethod getCanonicalizationMethod() {
            return c14nMethod;
        }
    }

}
