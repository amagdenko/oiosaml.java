package dk.itst.oiosaml.trust;

import static org.junit.Assert.*;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wsaddressing.Metadata;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.sp.model.OIOAssertion;

public class IssueTest extends TrustTests {
	private EndpointReference epr;
	private BasicX509Credential credential;
	private Assertion assertion;
	private BasicX509Credential stsCredential;
	private TrustClient client;
	private static final String ADDRESS = "http://localhost:8880/sts/STSService";
	
	@Before
	public void setUp() throws Exception {
		credential = credentialRepository.getCredential("/home/recht/download/TestMOCES1.pfx", "Test1234");
		assertion = (Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
		epr = SAMLUtil.buildXMLObject(EndpointReference.class);
		
		Address address = SAMLUtil.buildXMLObject(Address.class);
		address.setValue(ADDRESS);
		epr.setAddress(address);
		
		Metadata md = SAMLUtil.buildXMLObject(Metadata.class);
		epr.setMetadata(md);

		SecurityContext ctx = SAMLUtil.buildXMLObject(SecurityContext.class);
		md.getUnknownXMLObjects().add(ctx);

		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).setAudienceURI("tri-test1.trifork.com");
		assertion.setSignature(null);
		new OIOAssertion(assertion).sign(credential);
		
		Token token = new Token();
		token.setUsage("urn:liberty:security:tokenusage:2006-08:SecurityToken");
		ctx.getTokens().add(token);
		token.setAssertion(assertion);

		stsCredential = credentialRepository.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234");
		client = new TrustClient(epr, credential, stsCredential.getPublicKey());
		client.setAppliesTo("urn:appliesto");
		client.setUseReferenceForOnBehalfOf(false);
	}

	@Test
	public void testIssue() throws Exception {
		client.getToken(null);
	}
	
	@Test
	public void responseMustBeSigned() throws Exception {
		client.getToken(null);
		
		OIOSoapEnvelope env = getEnvelope(client.getLastRequestXML());
		assertTrue(env.isSigned());
		assertTrue(env.verifySignature(stsCredential.getPublicKey()));
	}
	
	@Test
	public void RSTRMustBeCollection() throws Exception {
		client.getToken(null);
		OIOSoapEnvelope env = getEnvelope(client.getLastRequestXML());
		assertTrue(env.getBody() instanceof RequestSecurityTokenResponseCollection);
	}
	
	@Test
	public void tokenMustBeAssertion() throws Exception {
		Element token = client.getToken(null);
		assertEquals(SAMLConstants.SAML20_NS, token.getNamespaceURI());
		assertEquals("Assertion", token.getLocalName());
	}
	
	@Test
	public void tokenMustBeHolderOfKey() throws Exception {
		Element token = client.getToken(null);
		OIOAssertion assertion = getAssertion(token);
		
		assertTrue(assertion.isHolderOfKey());
		
	}
	
	private OIOSoapEnvelope getEnvelope(String xml) {
		return new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(xml));
	}
	
	private OIOAssertion getAssertion(Element e) {
		return new OIOAssertion((Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(e)));
	}
}
