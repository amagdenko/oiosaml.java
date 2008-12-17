package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.ReplyTo;
import org.opensaml.ws.wsaddressing.To;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.common.SOAPException;


public class RequestTest extends AbstractTests {

	private Element req;
	private Element token;
	
	@Before
	public void setUp() {
		client.setAppliesTo(getProperty("endpoint"));
		token = client.getToken(null);

		SigningPolicy sp = new SigningPolicy(true);
		sp.addPolicy(To.ELEMENT_NAME, true);
		sp.addPolicy(MessageID.ELEMENT_NAME, true);
		sp.addPolicy(Action.ELEMENT_NAME, true);
		sp.addPolicy(Body.DEFAULT_ELEMENT_NAME, true);
		sp.addPolicy(ReplyTo.ELEMENT_NAME, true);
		sp.addPolicy(Timestamp.ELEMENT_NAME, true);
		client.setSigningPolicy(sp);

		String xml = getProperty("request");
		req = SAMLUtil.loadElementFromString(xml);
	}
	
	@Test
	public void testRequest() throws Exception {
		
		client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				assertEquals("echoResponse", result.getLocalName());
			}
		});
	}
	

	@Test
	public void unsignedTokenShouldFail() throws Exception {
		client.setToken((Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml")));
		
		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			if (!(e.getCause() instanceof SOAPException)) {
				e.getCause().printStackTrace();
				fail();
			}
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void noTokenShouldFail() throws Exception {
		client.setToken(null);
		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void mismatchingCertificatesShouldFail() throws Exception {
		client = new TrustClient(epr, TestHelper.getCredential(), stsCredential.getPublicKey());
		client.setAppliesTo(getProperty("endpoint"));
		client.setUseReferenceForOnBehalfOf(false);
		client.setToken((Assertion) SAMLUtil.unmarshallElement(token));
		
		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	
	@Test
	public void missingSignatureShouldFail() throws Exception {
		client.setSigningPolicy(new SigningPolicy(false));
		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void responseMustBeSigned() throws Exception {
		BasicX509Credential serviceCredential = credentialRepository.getCredential(getProperty("wsp.certificate"), getProperty("wsp.certificate.password"));

		client.sendRequest(req, getProperty("endpoint"), getProperty("action"), serviceCredential.getPublicKey(), new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				assertEquals("echoResponse", result.getLocalName());
			}
		});
	}
	
	@Test
	public void tokenWithWrongAudienceMustBeRejected() throws Exception {
		client.setAppliesTo("urn:testing");
		token = client.getToken(null);

		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());			
		}
	}
	

	@Test
	public void expiredTokenMustBeRejected() throws Exception {
		token = client.getToken(null, new DateTime().minusMinutes(5));

		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());			
		}
	}
	
}
