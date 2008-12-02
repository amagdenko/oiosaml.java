/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Trust Client.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
package dk.itst.oiosaml.trust;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
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
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.soap.soap11.impl.BodyBuilder;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.ws.soap.soap11.impl.HeaderBuilder;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.ReplyTo;
import org.opensaml.ws.wsaddressing.To;
import org.opensaml.ws.wssecurity.BinarySecurityToken;
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
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.RelatesTo;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.trust.internal.SignatureFactory;

/**
 * Wrap a generic SOAP envelope.
 *  
 *  This class adds some behavior to generic soap envelopes. Use this class to handle signatures, header elements, and other common operations.
 *
 *  @see SigningPolicy Use SigningPolicy to control which elements are signed.
 * @author recht
 *
 */
public class OIOSoapEnvelope {
	private static final Logger log = Logger.getLogger(OIOSoapEnvelope.class);
	
	private static final EnvelopeBuilder envelopeBuilder = new EnvelopeBuilder();
	private static final HeaderBuilder headerBuilder = new HeaderBuilder();
	private static final BodyBuilder bodyBuilder = new BodyBuilder();
	
    private Map<XMLObject, String> references = new LinkedHashMap<XMLObject, String>();
	private final Envelope envelope;
	private Security security;
	private Body body;
	private XMLSignatureFactory xsf;
	private Assertion securityToken;
	private SecurityTokenReference securityTokenReference;
	private final SigningPolicy signingPolicy;

	public OIOSoapEnvelope(Envelope envelope) {
		this(envelope, false, new SigningPolicy(true));
	}

	/**
	 * Wrap an existing envelope.
	 * 
	 * @param envelope
	 * @param signHeaderElements If <code>true</code>, all the header elements in the envelope are marked for signature.
	 */
	public OIOSoapEnvelope(Envelope envelope, boolean signHeaderElements, SigningPolicy signingPolicy) {
		this.signingPolicy = signingPolicy;
		if (envelope == null) throw new IllegalArgumentException("Envelope cannot be null");
		
		this.envelope = envelope;
		xsf = SignatureFactory.getInstance();

		security = SAMLUtil.getFirstElement(envelope.getHeader(), Security.class);
		if (signHeaderElements) {
			if (security == null) {
				security = SAMLUtil.buildXMLObject(Security.class);
				security.setMustUnderstand(new XSBooleanValue(true, true));
				envelope.getHeader().getUnknownXMLObjects().add(security);
			}
			for (XMLObject o : envelope.getHeader().getUnknownXMLObjects()) {
				if (o instanceof AttributeExtensibleXMLObject) {
					if (o instanceof Security) continue;
					addSignatureElement((AttributeExtensibleXMLObject) o);
				}
			}
		}
	}
	
	private OIOSoapEnvelope(Envelope envelope, MessageID msgId, XSAny framework, SigningPolicy signingPolicy) {
		this(envelope, false, signingPolicy);
		addSignatureElement(msgId);
		addSignatureElement(framework);
	}
	
	/**
	 * Builds a new soap envelope.
	 * 
	 * The signing policy is blank with default <code>true</code>.
	 *
	 * @see #buildEnvelope(String, SigningPolicy)
	 * @return
	 */
	public static OIOSoapEnvelope buildEnvelope(String soapVersion) {
		return buildEnvelope(soapVersion, new SigningPolicy(true));
	}
	
	/**
	 * Build a new soap envelope with standard OIO headers.
	 * 
	 *  Standard headers include sbf:Framework, wsa:MessageID, and an empty Security header.
	 */
	public static OIOSoapEnvelope buildEnvelope(String soapVersion, SigningPolicy signingPolicy) {
		Envelope env = envelopeBuilder.buildObject(soapVersion, "Envelope", "s");

		Header header = headerBuilder.buildObject(soapVersion, "Header", "s");
		env.setHeader(header);
		
		MessageID msgId = SAMLUtil.buildXMLObject(MessageID.class);
		msgId.setValue(UUID.randomUUID().toString());
		header.getUnknownXMLObjects().add(msgId);
		
		XSAny framework = new XSAnyBuilder().buildObject("urn:liberty:sb:2006-08", "Framework", "sbf");
		framework.getUnknownAttributes().put(new QName("version"), "2.0");
		framework.getUnknownAttributes().put(new QName("urn:liberty:sb:eGovprofile", "profile"), "urn:liberty:sb:profile:basicegovsimple");
		header.getUnknownXMLObjects().add(framework);
		
		Security security = SAMLUtil.buildXMLObject(Security.class);
		security.setMustUnderstand(new XSBooleanValue(true, true));
		env.getHeader().getUnknownXMLObjects().add(security);
		
		return new OIOSoapEnvelope(env, msgId, framework, signingPolicy);
	}

	/**
	 * Build a response envelope.
	 * @param signingPolicy The signing policy for the response.
	 */
	public static OIOSoapEnvelope buildResponse(SigningPolicy signingPolicy, OIOSoapEnvelope request) {
		OIOSoapEnvelope env = buildEnvelope(request.getSoapVersion(), signingPolicy);
		RelatesTo relatesTo = SAMLUtil.buildXMLObject(RelatesTo.class);
		relatesTo.setTextContent(request.getMessageID());
		env.addHeaderElement(relatesTo);
		return env;
	}
	
	public void setBody(XMLObject request) {
		body = bodyBuilder.buildObject(envelope.getElementQName().getNamespaceURI(), "Body", "s");
		body.getUnknownXMLObjects().add(request);
		addSignatureElement(body);
		
		envelope.setBody(body);
	}
	
	public void setAction(String action) {
		Action a = SAMLUtil.buildXMLObject(Action.class);
		a.setValue(action);
		addHeaderElement(a);
		addSignatureElement(a);
	}
	
	public void addSecurityToken(Assertion token) {
		security.getUnknownXMLObjects().add(token);
	}
	
	/**
	 * Insert a token and a SecurityTokenReference pointing to the token.
	 */
	public void addSecurityTokenReference(Assertion token) {
		if (token == null) return;
		
		token.detach();
		securityToken = token;
		addSecurityToken(token);
		
		securityTokenReference = createSecurityTokenReference(token);
		security.getUnknownXMLObjects().add(securityTokenReference);
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

	private SecurityTokenReference createSecurityTokenReference(BinarySecurityToken bst) {
		SecurityTokenReference str = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		org.opensaml.ws.wssecurity.Reference ref = SAMLUtil.buildXMLObject(org.opensaml.ws.wssecurity.Reference.class);
		ref.setValueType(bst.getValueType());
		ref.setURI("#" + bst.getId());
		str.setReference(ref);
		return str;
	}


	/**
	 * Check if this envelope relates to a specific message id.
	 */
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

	/**
	 * Add a timestamp to the Security header.
	 * @param timestampSkew How many minutes before the message should expire.
	 */
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
		if (references.isEmpty()) {
			log.debug("No elements to be signed, skipping signing process");
			return SAMLUtil.marshallObject(envelope);
		}
		CanonicalizationMethod canonicalizationMethod = xsf.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
		SignatureMethod signatureMethod = xsf.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

		KeyInfoFactory keyInfoFactory = xsf.getKeyInfoFactory();
		KeyInfo ki = generateKeyInfo(credential, keyInfoFactory);
    	
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
			
			
			transforms.add(SignatureFactory.getInstance().newTransform("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform",  new DOMStructure(tp)));
			Reference r = xsf.newReference("#"+securityTokenReference.getId(), digestMethod, transforms, null, null);
			refs.add(r);
		}

		// Create the SignedInfo
		SignedInfo signedInfo = xsf.newSignedInfo(canonicalizationMethod, signatureMethod, refs);
		
        
        
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

	private KeyInfo generateKeyInfo(X509Credential credential,
			KeyInfoFactory keyInfoFactory) throws XMLSignatureException {
		DOMStructure info;
        if (isHolderOfKey()) {
        	info = new DOMStructure(SAMLUtil.marshallObject(createSecurityTokenReference(securityToken)));
        } else {
        	BinarySecurityToken bst = SAMLUtil.buildXMLObject(BinarySecurityToken.class);
        	bst.setEncodingType("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        	bst.setValueType("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        	bst.setId(Utils.generateUUID());
        	
        	if (signingPolicy.sign(bst)) {
        		references.put(bst, bst.getId());
        	}
        	try {
				bst.setValue(Base64.encodeBytes(credential.getEntityCertificate().getEncoded(), Base64.DONT_BREAK_LINES));
			} catch (CertificateEncodingException e) {
				throw new XMLSignatureException(e);
			}
			info = new DOMStructure(SAMLUtil.marshallObject(createSecurityTokenReference(bst)));
			
			// assume that the first element is Timestamp (or the list is empty)
        	security.getUnknownXMLObjects().add(Math.min(1, security.getUnknownXMLObjects().size()), bst);
        }
    	KeyInfo ki = keyInfoFactory.newKeyInfo(Collections.singletonList(info));
		return ki;
	}
	
	/**
	 * Returns the {@link Envelope}. 
	 */
	public XMLObject getXMLObject() {
		return envelope;
	}
	
	/**
	 * Check if the envelope is signed. This does not validate the signature, it only checks for presence.
	 */
	public boolean isSigned() {
		boolean signed = SAMLUtil.getFirstElement(security, Signature.class) != null;
		log.debug("Envelope signed: " + signed);
		return signed;
	}
	
	public void setTo(String endpoint) {
		To to = SAMLUtil.buildXMLObject(To.class);
		to.setValue(endpoint);
		addHeaderElement(to);
		addSignatureElement(to);
	}

	public void setReplyTo(String replyTo) {
		ReplyTo reply = SAMLUtil.buildXMLObject(ReplyTo.class);
		Address addr = SAMLUtil.buildXMLObject(Address.class);
		addr.setValue(replyTo);
		reply.setAddress(addr);
		addHeaderElement(reply);
		addSignatureElement(reply);
	}

	/**
	 * Get an XML representation of the object.
	 */
	public String toXML() {
		Element e = SAMLUtil.marshallObject(envelope);
		return XMLHelper.nodeToString(e);
	}
	
	/**
	 * Get a header element of a specific type.
	 * @param type The header type.
	 * @return The header element, or <code>null</code> if no header of the given type was found.
	 */
	public <T extends XMLObject> T getHeaderElement(Class<T> type) {
		return SAMLUtil.getFirstElement(envelope.getHeader(), type);
	}
	
	/**
	 * Verify the envelope signature.
	 */
	public boolean verifySignature(PublicKey key) {
		if (!isSigned()) return false; 
		return new OIOSamlObject(security).verifySignature(key);
	}

	
	public boolean isHolderOfKey() {
		if (securityToken == null) return false;
		
		return new OIOAssertion(securityToken).isHolderOfKey();
	}
	
	public String getMessageID() {
		MessageID mid = SAMLUtil.getFirstElement(envelope.getHeader(), MessageID.class);
		if (mid == null) return null;
		
		return mid.getValue();
	}
	
	public void setUserInteraction(UserInteraction interaction, boolean redirect) {
		dk.itst.oiosaml.liberty.UserInteraction ui = SAMLUtil.getFirstElement(envelope.getHeader(), dk.itst.oiosaml.liberty.UserInteraction.class);
		if (ui != null) {
			ui.detach();
			envelope.getHeader().getUnknownXMLObjects().remove(ui);
		}
		if (interaction == UserInteraction.NONE) {
			return;
		}
		
		ui = SAMLUtil.buildXMLObject(dk.itst.oiosaml.liberty.UserInteraction.class);
		ui.setInteract(interaction.getValue());
		ui.setRedirect(redirect);
		addHeaderElement(ui);
		addSignatureElement(ui);
	}
	
	public String getSoapVersion() {
		return envelope.getElementQName().getNamespaceURI();
	}
	
	private String addSignatureElement(AttributeExtensibleXMLObject obj) {
		if (obj == null) return null;
		
		if (!signingPolicy.sign(obj)) return null; 
		
		String id = Utils.generateUUID();
		obj.getUnknownAttributes().put(TrustConstants.WSU_ID, id);
		
		references.put(obj, id);
		
		return id;
	}
	
	private void addHeaderElement(XMLObject element) {
		if (security == null) {
			envelope.getHeader().getUnknownXMLObjects().add(element);
		} else {
			envelope.getHeader().getUnknownXMLObjects().add(envelope.getHeader().getUnknownXMLObjects().size() - 1, element);
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
