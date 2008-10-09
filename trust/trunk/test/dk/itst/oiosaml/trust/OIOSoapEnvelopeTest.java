package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.WSAddressingConstants;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;


public class OIOSoapEnvelopeTest extends TrustTests {

	private OIOSoapEnvelope env;

	@Before
	public void setUp() {
		env = OIOSoapEnvelope.buildEnvelope();
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
		env.setBody(OIOIssueRequest.buildRequest());
		
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
	
	@Test(expected=RuntimeException.class)
	public void signFailsWhenEnvelopeIsEmpty() throws Exception {
		BasicX509Credential credential = TestHelper.getCredential();
		env.sign(credential);
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
		assertEquals(1, signature.getXMLSignature().getSignedInfo().getLength());
		
		Action action = (Action) envelope.getHeader().getUnknownXMLObjects(Action.ELEMENT_NAME).get(0);
		assertEquals("#" + action.getUnknownAttributes().get(TrustConstants.WSU_ID), signature.getXMLSignature().getSignedInfo().getReferencedContentBeforeTransformsItem(0).getSourceURI());
	
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
		assertFalse(signature.getKeyInfo().getX509Datas().isEmpty());
		X509Data x509 = signature.getKeyInfo().getX509Datas().get(0);
		assertEquals(1, x509.getX509Certificates().size());
		X509Certificate cert = x509.getX509Certificates().get(0);
		BasicX509Credential cred = new BasicX509Credential();

		String base64 = "-----BEGIN CERTIFICATE-----\n" + cert.getValue() + "\n-----END CERTIFICATE-----";
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
}
