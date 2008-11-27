package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;

import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.WSAddressingConstants;
import org.opensaml.ws.wssecurity.BinarySecurityToken;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.UserInteraction;
import dk.itst.oiosaml.sp.model.OIOAssertion;


public class OIOSoapEnvelopeTest extends TrustTests {

	private OIOSoapEnvelope env;

	@Before
	public void setUp() {
		env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP11_NS);
	}
	
	@Test
	public void testBuild() {
		assertNotNull(env);
		assertNotNull(env.getXMLObject());
		assertTrue(env.getXMLObject() instanceof Envelope);
		
		Envelope e = (Envelope) env.getXMLObject();
		assertNull(e.getBody());
		assertNotNull(e.getHeader());
		
		assertFalse(e.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).isEmpty());
	}
	
	
	@Test
	public void testAction() {
		env.setAction("action");
		Envelope e = (Envelope) env.getXMLObject();
		assertFalse(e.getHeader().getUnknownXMLObjects(Action.ELEMENT_NAME).isEmpty());
		Action a = (Action) e.getHeader().getUnknownXMLObjects(Action.ELEMENT_NAME).get(0);
		assertEquals("action", a.getValue());
		
		assertNotNull(a.getUnknownAttributes().get(TrustConstants.WSU_ID));
	}
	
	@Test
	public void testBody() {
		env.setBody(OIOIssueRequest.buildRequest().getXMLObject());
		
		Envelope e = (Envelope) env.getXMLObject();
		assertNotNull(e.getBody());
		assertNotNull(e.getBody().getUnknownAttributes().get(TrustConstants.WSU_ID));
	}
	
	@Test
	public void testTimestamp() {
		env.setTimestamp(5);
		Envelope e = (Envelope) env.getXMLObject();
		
		Security sec = (Security) e.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		Timestamp ts = (Timestamp) sec.getUnknownXMLObjects(Timestamp.ELEMENT_NAME).get(0);
		assertNotNull(ts.getCreated());
		assertNotNull(ts.getExpires());
		assertNotNull(ts.getUnknownAttributes().get(TrustConstants.WSU_ID));
	}
	
	@Test
	public void testAddSEcurityToken() {
		env.addSecurityToken(TestHelper.buildAssertion("rec", "aud"));
		
		Envelope e = (Envelope) env.getXMLObject();
		Security sec = (Security) e.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		assertFalse(sec.getUnknownXMLObjects(Assertion.DEFAULT_ELEMENT_NAME).isEmpty());
	}
	
	@Test
	public void testSign() throws Exception {
		env.setAction("action");
		
		BasicX509Credential credential = TestHelper.getCredential();
		Element e = env.sign(credential);
		assertEquals("Envelope", e.getLocalName());
		assertEquals(SOAPConstants.SOAP11_NS, e.getNamespaceURI());
		
		Envelope envelope = (Envelope) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(e));
		Security sec = (Security) envelope.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		assertFalse(sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).isEmpty());
		
		SignatureImpl signature = (SignatureImpl) sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
		assertEquals(4, signature.getXMLSignature().getSignedInfo().getLength());
		
		Action action = (Action) envelope.getHeader().getUnknownXMLObjects(Action.ELEMENT_NAME).get(0);
		
		boolean found = false;
		for (int i = 0; i < signature.getXMLSignature().getSignedInfo().getLength(); i++) {
			if (("#" + action.getUnknownAttributes().get(TrustConstants.WSU_ID)).equals(signature.getXMLSignature().getSignedInfo().getReferencedContentBeforeTransformsItem(i).getSourceURI())) {
				found = true;
			}
		}
		assertTrue(found);
	
		SignatureValidator validator = new SignatureValidator(credential);
		validator.validate(signature);
	}
	
	@Test
	public void testValidateFromX509data() throws Exception {
		env.setAction("action");
		
		BasicX509Credential credential = TestHelper.getCredential();
		Element e = env.sign(credential);
		
		Envelope envelope = (Envelope) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(e));
		Security sec = (Security) envelope.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		assertFalse(sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).isEmpty());
		
		SignatureImpl signature = (SignatureImpl) sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
		assertNotNull(signature.getKeyInfo());
		assertTrue(signature.getKeyInfo().getX509Datas().isEmpty());
		
		assertEquals(1, signature.getKeyInfo().getXMLObjects().size());
		assertTrue(signature.getKeyInfo().getXMLObjects().get(0) instanceof SecurityTokenReference);
		
		SecurityTokenReference ref = (SecurityTokenReference) signature.getKeyInfo().getXMLObjects().get(0);
		assertNotNull(ref.getReference());
		assertNotNull(ref.getReference().getURI());
		
		Element bstElement = e.getOwnerDocument().getElementById(ref.getReference().getURI().substring(1));
		assertNotNull(bstElement);
		
		BinarySecurityToken bst = (BinarySecurityToken) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(bstElement));
		
		BasicX509Credential cred = new BasicX509Credential();

		String base64 = "-----BEGIN CERTIFICATE-----\n" + bst.getValue() + "\n-----END CERTIFICATE-----";
		cred.setEntityCertificate((java.security.cert.X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(base64.getBytes())));
		SignatureValidator validator = new SignatureValidator(cred);
		validator.validate(signature);
		
	}
	
	@Test(expected=ValidationException.class)
	public void testInvalidSignature() throws Exception {
		env.setAction("action");
		
		BasicX509Credential credential = TestHelper.getCredential();
		Element e = env.sign(credential);
		Element actionElement = (Element) e.getElementsByTagNameNS(WSAddressingConstants.WSA_NS, "Action").item(0);
		actionElement.setTextContent("test");
		
		Envelope envelope = (Envelope) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(e));
		Security sec = (Security) envelope.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		Signature signature = (Signature) sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
		
		SignatureValidator validator = new SignatureValidator(credential);
		validator.validate(signature);
	}
	
	@Test
	public void testSignatureWithSignedAssertion() throws Exception {
		BasicX509Credential credential = TestHelper.getCredential();

		env.setAction("action");

		Assertion assertion = SAMLUtil.buildXMLObject(Assertion.class);
		assertion.setID("testing");
		new OIOAssertion(assertion).sign(credential);
		env.addSecurityToken(assertion);
		
		
		Element e = env.sign(credential);
		
		Envelope envelope = (Envelope) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(e));
		Security sec = (Security) envelope.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		
		SignatureImpl signature = (SignatureImpl) sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
		SignatureValidator validator = new SignatureValidator(credential);
		validator.validate(signature);

		assertion = (Assertion) sec.getUnknownXMLObjects(Assertion.DEFAULT_ELEMENT_NAME).get(0);
		assertTrue(new OIOAssertion(assertion).verifySignature(credential.getPublicKey()));
	}
	
	@Test
	public void testRelatesTo() {
		assertFalse(env.relatesTo("vlah"));
		
		
		Envelope e = (Envelope) env.getXMLObject();
		XSAny relatesTo = new XSAnyBuilder().buildObject(MessageID.ELEMENT_NAME.getNamespaceURI(), "RelatesTo", "wsa");
		relatesTo.setTextContent("id");
		
		e.getHeader().getUnknownXMLObjects().add(relatesTo);
		
		OIOSoapEnvelope env = new OIOSoapEnvelope(e);
		assertTrue(env.relatesTo("id"));
	}
	
	@Test
	public void testUserInteraction() throws Exception {
		assertNull(env.getHeaderElement(UserInteraction.class));
		
		env.setUserInteraction(dk.itst.oiosaml.trust.UserInteraction.IF_NEEDED, true);
		
		assertNotNull(env.getHeaderElement(UserInteraction.class));
		
		UserInteraction ui = env.getHeaderElement(UserInteraction.class);
		assertTrue(ui.redirect());
		assertEquals("InteractIfNeeded", ui.getInteract());
		
		System.out.println(env.toXML());
	}
	
	
	@Test
	public void testSecurityReferenceIsSignedWithSTRTransform() throws Exception {
		Assertion assertion = (Assertion) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
		env.addSecurityTokenReference(assertion);

		Security sec = env.getHeaderElement(Security.class);
		assertNotNull(SAMLUtil.getFirstElement(sec, Assertion.class));
		
		Element signed = env.sign(TestHelper.getCredential());
		env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(signed)));
		
		sec = env.getHeaderElement(Security.class);
		SecurityTokenReference str = SAMLUtil.getFirstElement(sec, SecurityTokenReference.class);
		assertNotNull(str);
		assertEquals(assertion.getID(), str.getKeyIdentifier().getValue());
		
		Signature sig = SAMLUtil.getFirstElement(sec, Signature.class);
		
		SignedInfo si = new XMLSignature(sig.getDOM(), null).getSignedInfo();
		boolean found = false;
		for (int i = 0; i < si.getLength(); i++) {
			XMLSignatureInput ref = si.getReferencedContentBeforeTransformsItem(i);
			System.out.println(ref.getSourceURI());
			if (("#" + str.getId()).equals(ref.getSourceURI())) {
				found = true;
			}
		}
		assertTrue(found);
	}
	
	@Test
	public void TestSOAP12() throws Exception {
		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP12_NS);
		
		String xml = env.toXML();
		assertTrue(xml.indexOf(SOAPConstants.SOAP12_NS) > -1);
		assertTrue(xml.indexOf(SOAPConstants.SOAP11_NS) == -1);
	}

	@Test
	public void testSigningPolicy() throws Exception {
		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP11_NS, new SigningPolicy(false));
		
		Element signed = env.sign(TestHelper.getCredential());
		assertEquals(0, signed.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Reference").getLength());
		
		SigningPolicy signingPolicy = new SigningPolicy(true);
		env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP11_NS, signingPolicy);
		
		signed = env.sign(TestHelper.getCredential());
		assertEquals(3, signed.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Reference").getLength());
		
		signingPolicy.addPolicy(MessageID.ELEMENT_NAME, false);
		env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP11_NS, signingPolicy);
		
		signed = env.sign(TestHelper.getCredential());
		assertEquals(2, signed.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Reference").getLength());
	}
	
	@Test
	public void testHeaderOrdering() throws Exception {
		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP11_NS);
		env.setAction("urn:action");

		Envelope e = (Envelope) env.getXMLObject();
		
		assertTrue(indexOf(e, Security.class) > indexOf(e, MessageID.class));
		assertTrue(indexOf(e, Security.class) > indexOf(e, Action.class));
	}
	
	private <T extends XMLObject> int  indexOf(Envelope e, Class<T> type) {
		T element = SAMLUtil.getFirstElement(e.getHeader(), type);
		return e.getHeader().getUnknownXMLObjects().indexOf(element);
	}
}
