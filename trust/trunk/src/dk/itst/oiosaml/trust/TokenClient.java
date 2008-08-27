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
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.trust;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.openliberty.xmltooling.Konstantz;
import org.openliberty.xmltooling.disco.SecurityContext;
import org.openliberty.xmltooling.security.Token;
import org.openliberty.xmltooling.wsa.Action;
import org.openliberty.xmltooling.wsa.EndpointReference;
import org.openliberty.xmltooling.wsse.Security;
import org.openliberty.xmltooling.wsu.Created;
import org.openliberty.xmltooling.wsu.Expires;
import org.openliberty.xmltooling.wsu.Timestamp;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.BRSConfiguration;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

public class TokenClient {
	private static final Logger log = Logger.getLogger(TokenClient.class);
	
	private String endpoint;
	private final EndpointReference epr;
	private final X509Credential credential;
	private String appliesTo;
	
	public TokenClient() {
		this((EndpointReference) SAMLUtil.unmarshallElementFromString(UserAssertionHolder.get().getAttribute("DiscoveryEPR").getValue()), 
				Utils.getCredential(BRSConfiguration.getStringPrefixedWithBRSHome(
				BRSConfiguration.getSystemConfiguration(), Constants.PROP_CERTIFICATE_LOCATION), 
				BRSConfiguration.getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD)));
	}
	
	public TokenClient(EndpointReference epr, X509Credential credential) {
		this.epr = epr;
		this.credential = credential;
		
		if (epr != null) {
			endpoint = epr.getAddress().getValue();
		}

		TrustBootstrap.bootstrap();
	}

	public Element request() {
		String xml = toXMLRequest();
		
		log.debug(xml);
		
		HttpSOAPClient client = new HttpSOAPClient();
		try {
			XMLObject res = client.wsCall(new LogUtil(getClass(), ""), endpoint, null, null, true, xml);
			
			log.debug("STS Response: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(res));
			
			if (res instanceof Fault) {
				Fault f = (Fault) res;
				throw new TrustException("Unable to retrieve STS token: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(f));
			} else {
				RequestSecurityTokenResponseCollection c = (RequestSecurityTokenResponseCollection) res;
				RequestSecurityTokenResponse tokenResponse = c.getResponses().get(0);
				
				return tokenResponse.getRequestedToken().getAssertions().get(0).getDOM();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private String addSignatureElement(XMLSignatureFactory xmf, Map<AttributeExtensibleXMLObject, String> references, AttributeExtensibleXMLObject obj) {
		String id = Utils.generateUUID();
		obj.getUnknownAttributes().put(new QName(Konstantz.WSU_NS, "Id", Konstantz.WSU_PREFIX), id);
		
		references.put(obj, id);
		
		return id;
	}
	
	private Element sign(XMLSignatureFactory xmf, Map<AttributeExtensibleXMLObject, String> references, Envelope env, String keyId) {
        try {
			CanonicalizationMethod canonicalizationMethod = xmf.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
			SignatureMethod signatureMethod = xmf.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

	        XSAnyBuilder builder = new XSAnyBuilder();
	        XSAny str = builder.buildObject(Konstantz.WSSE_NS, "SecurityTokenReference", Konstantz.WSSE_PREFIX);
	        XSAny kref = builder.buildObject(Konstantz.WSSE_NS, "Reference", Konstantz.WSSE_PREFIX);
	        kref.getUnknownAttributes().put(new QName("ValueType"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
	        kref.getUnknownAttributes().put(new QName("URI"), "#" + keyId);
	        str.getUnknownXMLObjects().add(kref);
//	        addSignatureElement(xmf, references, str);
	        
			List<Reference> refs = new ArrayList<Reference>();
			
			DigestMethod digestMethod = xmf.newDigestMethod(DigestMethod.SHA1, null);
			List<Transform> transforms = new ArrayList<Transform>(2);
			transforms.add(xmf.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#",new ExcC14NParameterSpec(Collections.singletonList("xsd"))));

			for (Map.Entry<AttributeExtensibleXMLObject, String> ref : references.entrySet()) {
				Reference r = xmf.newReference("#"+ref.getValue(), digestMethod, transforms, null, null);
				refs.add(r);
			}

			// Create the SignedInfo
			SignedInfo signedInfo = xmf.newSignedInfo(canonicalizationMethod, signatureMethod, refs);
			
	        KeyInfoFactory keyInfoFactory = xmf.getKeyInfoFactory();
	        X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(credential.getEntityCertificate()));
//	        KeyValue kv = keyInfoFactory.newKeyValue(credential.getPublicKey());
//	        KeyInfo ki = keyInfoFactory.newKeyInfo(Collections.singletonList(new DOMStructure(new XSAnyMarshaller().marshall(str))));
	        KeyInfo ki = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
	        
	        XMLSignature signature = xmf.newXMLSignature(signedInfo, ki);
	        
	        String xml = XMLHelper.nodeToString(SAMLUtil.marshallObject(env));
	        log.debug(xml);
	        Element element = SAMLUtil.loadElementFromString(xml);

	        Node security = element.getElementsByTagNameNS(Konstantz.WSSE_NS, "Security").item(0);
            
	        DOMSignContext signContext = new DOMSignContext(credential.getPrivateKey(), security); 
	        signContext.putNamespacePrefix("http://www.w3.org/2000/09/xmldsig#", "ds");
	        signContext.putNamespacePrefix("http://www.w3.org/2001/10/xml-exc-c14n#", "ec");

	        for (AttributeExtensibleXMLObject o : references.keySet()) {
	        	NodeList nl = element.getElementsByTagNameNS(o.getDOM().getNamespaceURI(), o.getDOM().getLocalName());
	        	for (int i = 0; i < nl.getLength(); i++) {
	        		Element e = (Element) nl.item(i);
	        		if (e.hasAttributeNS(Konstantz.WSU_NS, "Id")) {
	        			signContext.setIdAttributeNS(e, Konstantz.WSU_NS, "Id");
	        		}
	        	}
	        }
	        
	        // Marshal, generate (and sign) the detached XMLSignature. The DOM
	        // Document will contain the XML Signature if this method returns
	        // successfully.
	        // HIERARCHY_REQUEST_ERR: Raised if this node is of a type that does not allow children of the type of the newChild  node, or if the node to insert is one of this node's ancestors.
	        signature.sign(signContext);

	        return element;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		} catch (MarshalException e) {
			throw new RuntimeException(e);
		} catch (XMLSignatureException e) {
			throw new RuntimeException(e);
//		} catch (MarshallingException e) {
//			throw new RuntimeException(e);
		}
	}
	
	public String toXMLRequest() {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getSecurityContexts());
		
		XMLSignatureFactory xmf = getXMLSignature();
        Map<AttributeExtensibleXMLObject, String> references = new HashMap<AttributeExtensibleXMLObject, String>();
		
		
		RequestSecurityToken req = SAMLUtil.buildXMLObject(RequestSecurityToken.class);
		token.getAssertion().detach();
		req.setOnBehalfOf(token.getAssertion());
		req.setAppliesTo(appliesTo);
		req.setIssuer("urn:issuer");
		
		Body body = SAMLUtil.buildXMLObject(Body.class);
		body.getUnknownXMLObjects().add(req);
		addSignatureElement(xmf, references, body);

		// Build output...
		Envelope envelope = SAMLUtil.buildXMLObject(Envelope.class);
		envelope.setBody(body);

		Header header = SAMLUtil.buildXMLObject(Header.class);
		envelope.setHeader(header);
		
		Action action = new Action();
		action.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
		header.getUnknownXMLObjects().add(action);
		addSignatureElement(xmf, references, action);
		
		Security security = SAMLUtil.buildXMLObject(Security.class);
		security.getUnknownAttributes().put(new QName(SOAPConstants.SOAP11_NS, "mustUnderstand", SOAPConstants.SOAP11_PREFIX), "1");
		header.getUnknownXMLObjects().add(security);

		Timestamp timestamp = SAMLUtil.buildXMLObject(Timestamp.class);
		
		try {
			Created created = SAMLUtil.buildXMLObject(Created.class);
			GregorianCalendar gc = new GregorianCalendar();
			XMLGregorianCalendar cal = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
			created.setValue(cal.toXMLFormat());
			timestamp.setCreated(created);
			
			XSAny exp = new XSAnyBuilder().buildObject(Expires.DEFAULT_ELEMENT_NAME);
			gc.add(Calendar.MINUTE, 5);
			cal = DatatypeFactory.newInstance().newXMLGregorianCalendar(gc);
			exp.setTextContent(cal.toXMLFormat());
			timestamp.getUnknownXMLObjects().add(exp);
			
		} catch (DatatypeConfigurationException e1) {}
		security.getUnknownXMLObjects().add(timestamp);
		addSignatureElement(xmf, references, timestamp);
		
		security.getUnknownXMLObjects().add(token.getAssertion());
		
//        XSAny bst = new XSAnyBuilder().buildObject(Konstantz.WSSE_NS, "BinarySecurityToken", Konstantz.WSSE_PREFIX);
//        try {
//			bst.setTextContent(Base64.encodeBytes(credential.getEntityCertificate().getEncoded()));
//		} catch (CertificateEncodingException e) {
//			throw new RuntimeException(e);
//		}
//        bst.getUnknownAttributes().put(new QName("ValueType"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
//        bst.getUnknownAttributes().put(new QName("EncodingType"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
//        security.getUnknownXMLObjects().add(bst);
//        String keyId = addSignatureElement(xmf, references, bst);
		
		Element signed = sign(xmf, references, envelope, null);
		return XMLHelper.nodeToString(signed);
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}
	
	public void setAppliesTo(String appliesTo) {
		this.appliesTo = appliesTo;
	}

	private Token getToken(String usage, Collection<SecurityContext> contexts) {
		for (SecurityContext ctx : contexts) {
			for (Token t : ctx.getTokens()) {
				if (usage.equals(t.getUsage())) {
					return t;
				}
			}
			
		}
		throw new IllegalArgumentException("No token with usage type " + usage);
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
}
