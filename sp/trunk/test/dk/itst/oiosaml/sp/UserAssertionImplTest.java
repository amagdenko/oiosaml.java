package dk.itst.oiosaml.sp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.X509Certificate;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLConstants;

import dk.itst.oiosaml.sp.model.BRSSAMLConstants;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.TestHelper;
import dk.itst.oiosaml.sp.util.AttributeUtil;
import dk.itst.oiosaml.sp.util.BRSUtil;

public class UserAssertionImplTest {
	
	private OIOAssertion assertion;
	private AttributeStatement attributeStatement;
	private Assertion as;
	
	@BeforeClass
	public static void init() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Before
	public void setUp() {
		assertion = new OIOAssertion(createAssertion());
		attributeStatement = BRSUtil.buildXMLObject(AttributeStatement.class);
		assertion.getAssertion().getAttributeStatements().add(attributeStatement);
		as = assertion.getAssertion();
	}
	
	@Test
	public void testGetAllAttributes() {
		UserAssertionImpl ua = new UserAssertionImpl(assertion);
		assertEquals(0, ua.getAllAttributes().size());
		assertNull(ua.getAttribute("test"));
		
		attributeStatement.getAttributes().add(createAttribute("test", "test"));

		ua = new UserAssertionImpl(assertion);
		assertEquals(1, ua.getAllAttributes().size());
		assertNotNull(ua.getAttribute("test"));
		assertEquals("test", ua.getAttribute("test").getValue());
		
	}

	@Test
	public void testGetAssuranceLevel() {
		assertEquals(0, new UserAssertionImpl(assertion).getAssuranceLevel());
		attributeStatement.getAttributes().add(AttributeUtil.createAssuranceLevel(2));
		
		assertEquals(2, new UserAssertionImpl(assertion).getAssuranceLevel());
	}

	@Test
	public void testGetCVRNumberIdentifier() {
		assertNull(new UserAssertionImpl(assertion).getCVRNumberIdentifier());
		
		attributeStatement.getAttributes().add(AttributeUtil.createCVRNumberIdentifier("cvr"));
		assertEquals("cvr", new UserAssertionImpl(assertion).getCVRNumberIdentifier());
	}

	@Test
	public void testGetCertificateSerialNumber() {
		assertNull(new UserAssertionImpl(assertion).getCertificateSerialNumber());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_SERIAL_NUMBER_NAME, "cert"));
		assertEquals("cert", new UserAssertionImpl(assertion).getCertificateSerialNumber());
	}

	@Test
	public void testGetCommonName() {
		assertNull(new UserAssertionImpl(assertion).getCommonName());
		
		attributeStatement.getAttributes().add(AttributeUtil.createCommonName("name"));
		assertEquals("name", new UserAssertionImpl(assertion).getCommonName());
	}

	@Test
	public void testGetIssueTime() {
		assertNull(new UserAssertionImpl(assertion).getIssueTime());
		
		DateTime dt = new DateTime();
		as.setIssueInstant(dt);
		assertEquals(dt.toDate(), new UserAssertionImpl(assertion).getIssueTime());
	}

	@Test
	public void testGetIssuer() {
		assertNull(new UserAssertionImpl(assertion).getIssuer());
		as.setIssuer(BRSUtil.createIssuer("issuer"));
		
		assertEquals("issuer", new UserAssertionImpl(assertion).getIssuer());
		
	}

	@Test
	public void testGetMail() {
		assertNull(new UserAssertionImpl(assertion).getMail());
		
		attributeStatement.getAttributes().add(AttributeUtil.createMail("mail"));
		assertEquals("mail", new UserAssertionImpl(assertion).getMail());
	}

	@Test
	public void testGetSubject() {
		assertNull(new UserAssertionImpl(assertion).getNameIDFormat());
		assertNull(new UserAssertionImpl(assertion).getSubject());
		
		as.setSubject(BRSUtil.createSubject("subject", "url", new DateTime()));
		
		assertEquals(NameIDFormat.PERSISTENT, new UserAssertionImpl(assertion).getNameIDFormat());
		assertEquals("subject", new UserAssertionImpl(assertion).getSubject());
	}

	@Test
	public void testGetOrganizationName() {
		assertNull(new UserAssertionImpl(assertion).getOrganizationName());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_ORGANISATION_NAME_NAME, "org"));
		assertEquals("org", new UserAssertionImpl(assertion).getOrganizationName());
	}

	@Test
	public void testGetOrganizationUnit() {
		assertNull(new UserAssertionImpl(assertion).getOrganizationUnit());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_ORGANISATION_UNIT_NAME, "org"));
		assertEquals("org", new UserAssertionImpl(assertion).getOrganizationUnit());
	}

	@Test
	public void testGetPostalAddress() {
		assertNull(new UserAssertionImpl(assertion).getPostalAddress());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_POSTAL_ADDRESS_NAME, "postal"));
		assertEquals("postal", new UserAssertionImpl(assertion).getPostalAddress());
	}

	@Test
	public void testGetSessionExpireTime() {
		assertNull(new UserAssertionImpl(assertion).getSessionExpireTime());
	
		AuthnStatement st = BRSUtil.buildXMLObject(AuthnStatement.class);
		as.getAuthnStatements().add(st);
		DateTime dt = new DateTime();
		st.setSessionNotOnOrAfter(dt);
		
		assertEquals(dt.toDate(), new UserAssertionImpl(assertion).getSessionExpireTime());
	}

	@Test
	public void testGetSpecificationVersion() {
		assertNull(new UserAssertionImpl(assertion).getSpecificationVersion());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_SPECVER_NAME, "version"));
		assertEquals("version", new UserAssertionImpl(assertion).getSpecificationVersion());
	}

	@Test
	public void testGetSurname() {
		assertNull(new UserAssertionImpl(assertion).getSurname());
		
		attributeStatement.getAttributes().add(AttributeUtil.createSurname("name"));
		assertEquals("name", new UserAssertionImpl(assertion).getSurname());
	}

	@Test
	public void testGetTitle() {
		assertNull(new UserAssertionImpl(assertion).getTitle());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_TITLE_NAME, "title"));
		assertEquals("title", new UserAssertionImpl(assertion).getTitle());
		
	}

	@Test
	public void testGetUniqueAccountKey() {
		assertNull(new UserAssertionImpl(assertion).getUniqueAccountKey());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_UNIQUE_ACCOUNT_KEY_NAME, "key"));
		assertEquals("key", new UserAssertionImpl(assertion).getUniqueAccountKey());
	}

	@Test
	public void testGetUserId() {
		assertNull(new UserAssertionImpl(assertion).getUserId());
		
		attributeStatement.getAttributes().add(AttributeUtil.createUid("uid"));
		assertEquals("uid", new UserAssertionImpl(assertion).getUserId());
		
	}

	@Test
	public void testGetXML() {
		assertNotNull(new UserAssertionImpl(assertion).getXML());
	}

	@Test
	public void testIsSigned() {
		assertFalse(new UserAssertionImpl(assertion).isSigned());
		
		as.setSignature(BRSUtil.createSignature("key"));
		assertTrue(new UserAssertionImpl(assertion).isSigned());
	}
	
	@Test
	public void testGetCPRNumber() {
		assertNull(new UserAssertionImpl(assertion).getCPRNumber());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_CPR_NUMBER_NAME, "cpr"));
		assertEquals("cpr", new UserAssertionImpl(assertion).getCPRNumber());
	}
	
	@Test
	public void testGetEmployeeNumber() {
		assertNull(new UserAssertionImpl(assertion).getRIDNumber());
		
		attributeStatement.getAttributes().add(AttributeUtil.createRidNumberIdentifier("rid"));
		assertEquals("rid", new UserAssertionImpl(assertion).getRIDNumber());
	}

	@Test
	public void testPIDNumber() {
		assertNull(new UserAssertionImpl(assertion).getPIDNumber());
		
		attributeStatement.getAttributes().add(AttributeUtil.createPidNumberIdentifier("pid"));
		assertEquals("pid", new UserAssertionImpl(assertion).getPIDNumber());
	}

	@Test
	public void testGetPseudonym() {
		assertNull(new UserAssertionImpl(assertion).getPseudonym());
		
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_PSEUDONYM_NAME, "ps"));
		assertEquals("ps", new UserAssertionImpl(assertion).getPseudonym());
	}
	
	@Test
	public void testGetUserCertificate() throws Exception {
		assertNull(new UserAssertionImpl(assertion).getUserCertificate());
		
		Credential cred = TestHelper.getCredential();
		X509Certificate cert = TestHelper.getCertificate(cred);

		attributeStatement.getAttributes().add(AttributeUtil.createUserCertificate(Base64.encodeBytes(cert.getEncoded())));
		
		assertEquals(cert, new UserAssertionImpl(assertion).getUserCertificate());
		
		attributeStatement.getAttributes().clear();
		attributeStatement.getAttributes().add(AttributeUtil.createUserCertificate("test" + Base64.encodeBytes(cert.getEncoded())));
		
		try {
			new UserAssertionImpl(assertion).getUserCertificate();
			fail("certificate is invalid");
		} catch (RuntimeException e) { }
	}
	
	@Test
	public void testIsYouthCertificate() {
		assertNull(new UserAssertionImpl(assertion).isYouthCertificate());
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_YOUTH_CERTIFICATE_NAME, "true"));
		assertEquals(true, new UserAssertionImpl(assertion).isYouthCertificate());

		attributeStatement.getAttributes().clear();
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_YOUTH_CERTIFICATE_NAME, "false"));
		assertEquals(false, new UserAssertionImpl(assertion).isYouthCertificate());
	}
	
	@Test
	public void testProfileCompliance() {
		assertFalse(new UserAssertionImpl(assertion).isOCESProfileCompliant());
		assertFalse(new UserAssertionImpl(assertion).isOIOSAMLCompliant());
		
		as.setSignature(BRSUtil.createSignature("key"));
		as.setIssuer(BRSUtil.createIssuer("issuer"));
		as.setSubject(BRSUtil.createSubject("id", "url", new DateTime()));
		AuthnStatement st = BRSUtil.buildXMLObject(AuthnStatement.class);
		st.setSessionIndex("idx");
		as.getAuthnStatements().add(st);
		
		attributeStatement.getAttributes().add(AttributeUtil.createCommonName("name"));
		attributeStatement.getAttributes().add(AttributeUtil.createSurname("surname"));
		attributeStatement.getAttributes().add(AttributeUtil.createUid("uid"));
		attributeStatement.getAttributes().add(AttributeUtil.createMail("mail"));
		
		attributeStatement.getAttributes().add(AttributeUtil.createAssuranceLevel(2));
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_SPECVER_NAME, "DK-SAML-2.0"));
		
		assertTrue(new UserAssertionImpl(assertion).isOIOSAMLCompliant());
		assertFalse(new UserAssertionImpl(assertion).isOCESProfileCompliant());
		
		as.getSubject().getNameID().setFormat(NameIDFormat.X509SUBJECT.getFormat());
		attributeStatement.getAttributes().add(AttributeUtil.createSerialNumber("number"));
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_YOUTH_CERTIFICATE_NAME, "true"));
		attributeStatement.getAttributes().add(AttributeUtil.createPidNumberIdentifier("pid"));
		attributeStatement.getAttributes().remove(2);
		attributeStatement.getAttributes().add(AttributeUtil.createUid("PID:pid"));

		assertTrue(new UserAssertionImpl(assertion).isOIOSAMLCompliant());
		assertTrue(new UserAssertionImpl(assertion).isOCESProfileCompliant());
		
		attributeStatement.getAttributes().add(AttributeUtil.createRidNumberIdentifier("rid"));
		assertTrue(new UserAssertionImpl(assertion).isOIOSAMLCompliant());
		assertFalse(new UserAssertionImpl(assertion).isOCESProfileCompliant());
	}
	
	@Test
	public void testIsPersistentCompliant() {
		as.setSubject(BRSUtil.createSubject("id", "url", new DateTime()));
		as.getSubject().getNameID().setFormat(NameIDFormat.PERSISTENT.getFormat());
		attributeStatement.getAttributes().add(AttributeUtil.createAssuranceLevel(2));
		attributeStatement.getAttributes().add(createAttribute(BRSSAMLConstants.ATTRIBUTE_SPECVER_NAME, "DK-SAML-2.0"));
		
		assertTrue(new UserAssertionImpl(assertion).isPersistentPseudonymProfileCompliant());
		
		attributeStatement.getAttributes().add(AttributeUtil.createUid("PID:pid"));
		assertFalse(new UserAssertionImpl(assertion).isPersistentPseudonymProfileCompliant());
	}
	
	@Test
	public void testGetAssertionId() throws Exception {
		assertEquals(as.getID(), new UserAssertionImpl(assertion).getAssertionId());
	}
	
	
	private Assertion createAssertion() {
		return BRSUtil.buildXMLObject(Assertion.class);
	}
	
	private Attribute createAttribute(String name, String value) {
		Attribute attr = BRSUtil.buildXMLObject(Attribute.class);
		attr.setName(name);
		XSAnyBuilder builder = new XSAnyBuilder();
		XSAny ep = builder.buildObject(SAMLConstants.SAML20_NS,
				AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME,
				SAMLConstants.SAML20_PREFIX);
		ep.setTextContent(value);
		ep.getUnknownAttributes().put(AttributeUtil.XSI_TYPE_ATTRIBUTE_NAME, AttributeUtil.XS_STRING);
		ep.addNamespace(new Namespace(XMLConstants.XSI_NS, XMLConstants.XSI_PREFIX));
		attr.getAttributeValues().add(ep);
		return attr;
	}
}
