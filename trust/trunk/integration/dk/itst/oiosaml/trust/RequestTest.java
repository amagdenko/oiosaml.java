package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import javax.xml.namespace.QName;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.common.SOAPException;


public class RequestTest extends AbstractTests {

	private static final String SERVICE_URL = "http://localhost:8880/poc-provider/ProviderService";
	private static final String SERVICE_ACTION = "http://provider.poc.saml.itst.dk/Provider/echoRequest";
	private Element req;
	private Element token;
	
	@Before
	public void setUp() {
		token = client.getToken(null);

		String xml = "<ns2:echo xmlns:ns2=\"http://poc.oiosaml.itst.dk/\"></ns2:echo>";
		req = SAMLUtil.loadElementFromString(xml);
	}
	
	@Test
	public void testRequest() throws Exception {
		
		client.sendRequest(req, SERVICE_URL, SERVICE_ACTION, null, new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				assertEquals("echoResponse", result.getLocalName());
			}
		});
	}
	

	@Test
	public void unsignedTokenShouldFail() throws Exception {
		client.setToken((Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml")));
		
		try {
			client.sendRequest(req, SERVICE_URL, SERVICE_ACTION, null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void noTokenShouldFail() throws Exception {
		client.setToken(null);
		try {
			client.sendRequest(req, SERVICE_URL, SERVICE_ACTION, null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void mismatchingCertificatesShouldFail() throws Exception {
		client = new TrustClient(epr, TestHelper.getCredential(), stsCredential.getPublicKey());
		client.setAppliesTo("urn:appliesto");
		client.setUseReferenceForOnBehalfOf(false);
		client.setToken((Assertion) SAMLUtil.unmarshallElement(token));
		
		try {
			client.sendRequest(req, SERVICE_URL, SERVICE_ACTION, null, null);
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
			client.sendRequest(req, SERVICE_URL, SERVICE_ACTION, null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
		
	}
	
}
