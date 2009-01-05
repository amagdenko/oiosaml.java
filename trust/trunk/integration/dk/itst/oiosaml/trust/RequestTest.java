package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.ReplyTo;
import org.opensaml.ws.wsaddressing.To;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.common.SOAPException;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.model.OIOSamlObject;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.SOAPClient;


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
		
		client.setProtectTokens(Boolean.valueOf(getProperty("protectTokens")));
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
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurityToken"), ex.getFault().getCode().getValue());			
		}
	}
	

	@Test
	public void expiredTokenMustBeRejected() throws Exception {
		token = client.getToken(null, new DateTime().minusDays(5));

		try {
			client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurityToken"), ex.getFault().getCode().getValue());			
		}
	}
	
	@Test
	public void allHeadersMustBeSigned() throws Exception {
		SigningPolicy sp = new SigningPolicy(true);
		sp.addPolicy(To.ELEMENT_NAME, false);
		
		client.setSigningPolicy(sp);
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
	public void tokensCanBeReplacedWhenNotProtected() throws Exception {
		client.getToken(null);
		
		client.setProtectTokens(false);
		SOAPClientStub soapClient = new SOAPClientStub();
		client.setSOAPClient(soapClient);
		client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
		
		Element env = SAMLUtil.loadElementFromString(soapClient.xml);
		NodeList nl = env.getElementsByTagNameNS(TrustConstants.WSSE_NS, "KeyIdentifier");
		for (int i = 0; i < nl.getLength(); i++) {
			Element item = (Element) nl.item(i);
			item.setTextContent(token.getAttribute("ID"));
		}
		
		Element a = (Element) env.getElementsByTagNameNS(Assertion.TYPE_NAME.getNamespaceURI(), "Assertion").item(0);
		Node localToken = a.getOwnerDocument().adoptNode(token);
		a.getParentNode().replaceChild(localToken, a);
		
		new HttpSOAPClient().wsCall(getProperty("endpoint"), null, null, true, XMLHelper.nodeToString(env), getProperty("action"));
	}
	
	@Test(expected=SOAPException.class)
	public void securityTokenReferenceCannotBeReplaced() throws Exception {
		client.getToken(null);
		
		client.setProtectTokens(true);
		SOAPClientStub soapClient = new SOAPClientStub();
		client.setSOAPClient(soapClient);
		client.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
		
		Element env = SAMLUtil.loadElementFromString(soapClient.xml);
		NodeList nl = env.getElementsByTagNameNS(TrustConstants.WSSE_NS, "KeyIdentifier");
		Element item = (Element) nl.item(nl.getLength() - 1);
		item.setTextContent(token.getAttribute("ID"));
		
		Element a = (Element) env.getElementsByTagNameNS(Assertion.TYPE_NAME.getNamespaceURI(), "Assertion").item(0);
		Node localToken = a.getOwnerDocument().adoptNode(token);
		a.getParentNode().insertBefore(localToken, a);
		
		new HttpSOAPClient().wsCall(getProperty("endpoint"), null, null, true, XMLHelper.nodeToString(env), getProperty("action"));
		fail();
	}
	
	private static class SOAPClientStub implements SOAPClient {
		private String xml;

		public Envelope wsCall(XMLObject arg0, LogUtil arg1, String arg2, String arg3, String arg4, boolean arg5) throws IOException {
			return null;
		}

		public XMLObject wsCall(OIOSamlObject arg0, LogUtil arg1, String arg2, String arg3, String arg4, boolean arg5) throws IOException {
			return null;
		}

		public Envelope wsCall(String arg0, String arg1, String arg2, boolean arg3, String xml, String arg5) throws IOException,
				SOAPException {
			
			this.xml = xml;
			return (Envelope) OIOSoapEnvelope.buildResponse(new SigningPolicy(false), new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(xml))).getXMLObject();
		}
		
	}
}
