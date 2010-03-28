package dk.itst.saml.sts;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.BinarySecurityToken;
import org.opensaml.ws.wssecurity.Created;
import org.opensaml.ws.wssecurity.Expires;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.ws.wstrust.Claims;
import org.opensaml.ws.wstrust.Lifetime;
import org.opensaml.ws.wstrust.OnBehalfOf;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestedAttachedReference;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.ws.wstrust.RequestedUnattachedReference;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.liberty.ActAs;
import dk.itst.oiosaml.liberty.ClaimType;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.NameIDFormat;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.AttributeUtil;
import dk.itst.oiosaml.trust.OIOSoapEnvelope;
import dk.itst.oiosaml.trust.SigningPolicy;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustConstants;
import dk.itst.oiosaml.trust.internal.SignatureFactory;

public class TokenService extends HttpServlet {
	private static CredentialRepository credentialRepository = new CredentialRepository();
	
	private static final Logger log = Logger.getLogger(TokenService.class);

	private Configuration cfg;
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
		
		SAMLConfiguration.setConfigurationName("sts");
		SAMLConfiguration.setHomeProperty(null);
		cfg = SAMLConfiguration.getSystemConfiguration();
		
		log.info("Configured OIOSAML to " + System.getProperty("user.home") + "/.oiosaml/sts.properties");
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		BasicX509Credential credential = credentialRepository.getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(cfg, "sts.certificate.location"), cfg.getString("sts.certificate.password"));

		String xml = IOUtils.toString(req.getInputStream());
		log.debug("Received request: " + xml);
		
		OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(xml));
		BinarySecurityToken bst = SAMLUtil.getFirstElement(env.getHeaderElement(Security.class), BinarySecurityToken.class);
		
		RequestSecurityToken rst = (RequestSecurityToken) env.getBody();
		OnBehalfOf obo = SAMLUtil.getFirstElement(rst, OnBehalfOf.class);
		ActAs actAs = SAMLUtil.getFirstElement(rst, ActAs.class);
		
		Assertion bootstrapAssertion = null;
		if (obo != null && obo.getUnknownXMLObject() instanceof Assertion) {
			bootstrapAssertion = (Assertion) obo.getUnknownXMLObject();
		}
		if (actAs != null && actAs.getUnknownXMLObject() instanceof Assertion) {
			bootstrapAssertion = (Assertion) actAs.getUnknownXMLObject();
		}
		OIOAssertion bootstrap = null;
		if (bootstrapAssertion != null) {
			bootstrap = new OIOAssertion(bootstrapAssertion);
		} else {
			log.error("No SAML Assertion in OnBehalfOf");
		}
		DateTime expire;
		Lifetime lifetime = SAMLUtil.getFirstElement(rst, Lifetime.class);
		if (lifetime != null && lifetime.getExpires() != null) {
			expire = lifetime.getExpires().getDateTime();
		} else {
			expire = new DateTime().plusMinutes(5);
		}
		
		OIOSoapEnvelope res = OIOSoapEnvelope.buildResponse(new SigningPolicy(true), env);
		Envelope tmp = (Envelope) SAMLUtil.unmarshallElementFromString(res.toXML());
		tmp.getHeader().getUnknownXMLObjects().remove(tmp.getHeader().getUnknownXMLObjects(new QName("urn:liberty:sb:2006-08", "Framework")).get(0));
		res = new OIOSoapEnvelope(tmp, true, new SigningPolicy(true));
		
		RequestSecurityTokenResponseCollection rstrc = SAMLUtil.buildXMLObject(RequestSecurityTokenResponseCollection.class);
		RequestSecurityTokenResponse rstr = SAMLUtil.buildXMLObject(RequestSecurityTokenResponse.class);
		rstrc.getRequestSecurityTokenResponses().add(rstr);
		
		String to = setAppliesTo(rst, rstr);
		rstr.setContext(rst.getContext());
		
		TokenType tokenType = SAMLUtil.buildXMLObject(TokenType.class);
		tokenType.setValue(TrustConstants.TOKEN_TYPE_SAML_20);
		rstr.getUnknownXMLObjects().add(tokenType);
		
		Lifetime lt = SAMLUtil.buildXMLObject(Lifetime.class);
		Expires expires = SAMLUtil.buildXMLObject(Expires.class);
		Created created = SAMLUtil.buildXMLObject(Created.class);
		created.setDateTime(new DateTime());
		expires.setDateTime(expire);
		lt.setExpires(expires);
		lt.setCreated(created);
		rstr.getUnknownXMLObjects().add(lt);
		
		RequestedSecurityToken requestedSecurityToken = SAMLUtil.buildXMLObject(RequestedSecurityToken.class);
		rstr.getUnknownXMLObjects().add(requestedSecurityToken);
		Assertion assertion = generateAssertion(req, bootstrap, to, bst.getValue(), credential, expire, SAMLUtil.getFirstElement(rst, Claims.class));
		requestedSecurityToken.setUnknownXMLObject(assertion);
		
		RequestedAttachedReference attached = SAMLUtil.buildXMLObject(RequestedAttachedReference.class);
		attached.setSecurityTokenReference(generateTokenReference(assertion));
		rstr.getUnknownXMLObjects().add(attached);
		
		RequestedUnattachedReference unattachedReference = SAMLUtil.buildXMLObject(RequestedUnattachedReference.class);
		unattachedReference.setSecurityTokenReference(generateTokenReference(assertion));
		rstr.addNamespace(new Namespace(TrustConstants.WSSE11_NS, "wsse11"));
		rstr.getUnknownXMLObjects().add(unattachedReference);
		
		
		res.setBody(rstrc);
		res.setTimestamp(5);
		res.setAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal");
		res.setTo("http://www.w3.org/2005/08/addressing/anonymous");
		
		try {
			xml = XMLHelper.nodeToString(res.sign(credential));
			resp.setContentType("text/xml; charset=utf-8");
			resp.setContentLength(xml.getBytes("UTF-8").length);
			IOUtils.write(xml, resp.getOutputStream(), "UTF-8");
			
			log.debug("Response: " + xml);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String setAppliesTo(RequestSecurityToken rst, RequestSecurityTokenResponse rstr) {
		EndpointReference epr = SAMLUtil.getFirstElement(SAMLUtil.getFirstElement(rst, AppliesTo.class), EndpointReference.class);
		log.debug("AppliesTo EPR: " + epr);
		
		if (epr == null) return null;
		
		AppliesTo appliesTo = SAMLUtil.buildXMLObject(AppliesTo.class);
		EndpointReference reference = SAMLUtil.buildXMLObject(EndpointReference.class);
		Address addr = SAMLUtil.buildXMLObject(Address.class);
		reference.setAddress(addr);
		addr.setValue(epr.getAddress().getValue());
		appliesTo.getUnknownXMLObjects().add(reference);
		
		rstr.getUnknownXMLObjects().add(appliesTo);
		return epr.getAddress().getValue();
	}

	private SecurityTokenReference generateTokenReference(Assertion assertion) {
		SecurityTokenReference tokenReference = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		KeyIdentifier keyIdentifier = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		keyIdentifier.setValue(assertion.getID());
		keyIdentifier.getUnknownAttributes().put(TrustConstants.VALUE_TYPE, TrustConstants.SAMLID);
		keyIdentifier.setEncodingType(null);
		tokenReference.getUnknownAttributes().put(TrustConstants.TOKEN_TYPE, TrustConstants.TOKEN_TYPE_SAML_20);
		tokenReference.getUnknownXMLObjects().add(keyIdentifier);
		return tokenReference;
	}

	private Assertion generateAssertion(HttpServletRequest req, OIOAssertion bootstrap, String to, String x509, BasicX509Credential credential, DateTime expire, Claims claims) {
		Assertion a = SAMLUtil.buildXMLObject(Assertion.class);
		a.setID(Utils.generateUUID());
		a.setIssueInstant(new DateTime(DateTimeZone.UTC));
		
		a.setIssuer(SAMLUtil.createIssuer(cfg.getString("sts.entityId")));
		Subject subject = SAMLUtil.buildXMLObject(Subject.class);
		
		if (bootstrap != null) {
			NameID nameID = bootstrap.getAssertion().getSubject().getNameID();
			if (nameID != null) {
				NameID nameId = SAMLUtil.createNameID(nameID.getValue());
				nameId.setFormat(nameID.getFormat());
				subject.setNameID(nameId);
			}
		} else {
			String c = "-----BEGIN CERTIFICATE-----\n" + x509 + "\n-----END CERTIFICATE-----\n";
			try {
				java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) CertificateFactory.getInstance("x509").generateCertificate(new ByteArrayInputStream(c.getBytes()));
				NameID nameId = SAMLUtil.createNameID(cert.getSubjectDN().getName());
				nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
				subject.setNameID(nameId);
			} catch (CertificateException e) {
				log.error("Unable to read certificate", e);
			}
		}
		
		SubjectConfirmation confirmation = SAMLUtil.buildXMLObject(SubjectConfirmation.class);
		confirmation.setMethod(OIOSAMLConstants.METHOD_HOK);
		confirmation.setNameID(SAMLUtil.createNameID(req.getRequestURL().toString()));
		confirmation.getNameID().setFormat(NameIDFormat.ENTITY.getFormat());
		
		SubjectConfirmationData data = SAMLUtil.buildXMLObject(SubjectConfirmationData.class);
		data.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type", "xsi"), data.getElementQName().getPrefix() + ":KeyInfoConfirmationDataType");
		
		KeyInfo keyInfo = SAMLUtil.buildXMLObject(KeyInfo.class);
		X509Data x509data = SAMLUtil.buildXMLObject(X509Data.class);
		X509Certificate cert = SAMLUtil.buildXMLObject(X509Certificate.class);
		cert.setValue(x509);
		x509data.getX509Certificates().add(cert);
		keyInfo.getX509Datas().add(x509data);
		data.getUnknownXMLObjects().add(keyInfo);
		confirmation.setSubjectConfirmationData(data);
		
		subject.getSubjectConfirmations().add(confirmation);
		a.setSubject(subject);
		
		a.setConditions(SAMLUtil.createAudienceCondition(to));
		a.getConditions().setNotOnOrAfter(expire);
		
		
		if (bootstrap != null && (claims == null || (claims != null && !claims.getUnknownXMLObjects().isEmpty()))) {
			for (AttributeStatement as : bootstrap.getAssertion().getAttributeStatements()) {
				AttributeStatement newAs = SAMLUtil.buildXMLObject(AttributeStatement.class);
				
				for (Attribute attr : as.getAttributes()) {
					if (!hasClaim(attr.getName(), claims)) continue;
					Attribute newAttr = SAMLUtil.buildXMLObject(Attribute.class);
					newAs.getAttributes().add(newAttr);
					
					newAttr.setFriendlyName(attr.getFriendlyName());
					newAttr.setName(attr.getName());
					newAttr.setNameFormat(attr.getNameFormat());
					
					newAttr.getAttributeValues().add(AttributeUtil.createAttributeValue(AttributeUtil.extractAttributeValueValue(attr)));
				}
				if (!newAs.getAttributes().isEmpty()) {
					a.getAttributeStatements().add(newAs);
				}
			}
		}
		a.addNamespace(new Namespace(XMLConstants.W3C_XML_SCHEMA_NS_URI, "xs"));
		a.addNamespace(new Namespace(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "xsi"));
		
//		OIOAssertion oa = new OIOAssertion(SAMLUtil.clone(a));
//		oa.sign(credential);
//		
//		return (Assertion) SAMLUtil.unmarshallElementFromString(oa.toXML());
		
		try {
			Element signed = sign(a, credential);
			log.debug("Signed assertion: " + XMLHelper.nodeToString(signed));
			return (Assertion) SAMLUtil.unmarshallElement(signed);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	
	public Element sign(Assertion assertion, X509Credential credential) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Map<XMLObject, String> references = new HashMap<XMLObject, String>();
		references.put(assertion, assertion.getID());
		
		XMLSignatureFactory xsf = SignatureFactory.getInstance();
		
		CanonicalizationMethod canonicalizationMethod = xsf.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
		SignatureMethod signatureMethod = xsf.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

		KeyInfoFactory keyInfoFactory = xsf.getKeyInfoFactory();
		javax.xml.crypto.dsig.keyinfo.KeyInfo ki = keyInfoFactory.newKeyInfo(Collections.singletonList(keyInfoFactory.newX509Data(Collections.singletonList(credential.getEntityCertificate()))));
    	
    	List<Reference> refs = new ArrayList<Reference>();
		
		DigestMethod digestMethod = xsf.newDigestMethod(DigestMethod.SHA1, null);
		List<Transform> transforms = new ArrayList<Transform>(2);
		transforms.add(xsf.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", (TransformParameterSpec)null));
		transforms.add(xsf.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#",(ExcC14NParameterSpec)null));

		for (Map.Entry<XMLObject, String> ref : references.entrySet()) {
			Reference r = xsf.newReference("#"+ref.getValue(), digestMethod, transforms, null, null);
			refs.add(r);
		}

		
		SAMLUtil.marshallObject(assertion);
		
		// Create the SignedInfo
		SignedInfo signedInfo = xsf.newSignedInfo(canonicalizationMethod, signatureMethod, refs);
        
        
        String signatureId = Utils.generateUUID();
		XMLSignature signature = xsf.newXMLSignature(signedInfo, ki, null, signatureId, null);
        
        String xml = XMLHelper.nodeToString(assertion.getDOM());
        log.debug("Signing assertion: " + xml);
        Element element = SAMLUtil.loadElementFromString(xml);
        
        Node next = element.getElementsByTagNameNS(Subject.DEFAULT_ELEMENT_NAME.getNamespaceURI(), Subject.DEFAULT_ELEMENT_LOCAL_NAME).item(0);
        
        DOMSignContext signContext = new DOMSignContext(credential.getPrivateKey(), element, next); 
        signContext.putNamespacePrefix(SAMLConstants.XMLSIG_NS, SAMLConstants.XMLSIG_PREFIX);
        signContext.putNamespacePrefix(SAMLConstants.XMLENC_NS, SAMLConstants.XMLENC_PREFIX);

        for (XMLObject o : references.keySet()) {
        	fixIdAttributes(element, o);
        }
        
        // Marshal, generate (and sign) the detached XMLSignature. The DOM
        // Document will contain the XML Signature if this method returns
        // successfully.
        // HIERARCHY_REQUEST_ERR: Raised if this node is of a type that does not allow children of the type of the newChild  node, or if the node to insert is one of this node's ancestors.
        signature.sign(signContext);

        return element;
	}
	
	private boolean hasClaim(String attribute, Claims claims) {
		if (claims == null) return true;
		
		List<XMLObject> types = claims.getUnknownXMLObjects(ClaimType.ELEMENT_NAME);
		for (XMLObject t : types) {
			ClaimType type = (ClaimType) t;
			if (attribute.equals(type.getUri())) {
				return true;
			}
		}
		return false;
	}

	private void fixIdAttributes(Element env, XMLObject obj) {
		if (obj == null) return;
		
		if (log.isDebugEnabled()) log.debug("Fixing id attribute on " + obj);
		
    	NodeList nl = env.getElementsByTagNameNS(obj.getDOM().getNamespaceURI(), obj.getDOM().getLocalName());
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
}
