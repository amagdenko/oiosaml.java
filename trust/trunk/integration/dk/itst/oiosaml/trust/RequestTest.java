package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
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
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
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
	private Assertion token;
	private BasicX509Credential serviceCredential;
	private ServiceClient serviceClient;
	
	@Before
	public void setUp() {
		client.setAppliesTo(getProperty("endpoint"));
		token = client.getToken(null);
		serviceClient = client.getServiceClient();

		SigningPolicy sp = new SigningPolicy(true);
		sp.addPolicy(To.ELEMENT_NAME, true);
		sp.addPolicy(MessageID.ELEMENT_NAME, true);
		sp.addPolicy(Action.ELEMENT_NAME, true);
		sp.addPolicy(Body.DEFAULT_ELEMENT_NAME, true);
		sp.addPolicy(ReplyTo.ELEMENT_NAME, true);
		sp.addPolicy(Timestamp.ELEMENT_NAME, true);
		serviceClient.setSigningPolicy(sp);

		String xml = getProperty("request");
		req = SAMLUtil.loadElementFromString(xml);
		
		serviceClient.setProtectTokens(Boolean.valueOf(getProperty("protectTokens")));
		serviceCredential = credentialRepository.getCredential(getProperty("wsp.certificate"), getProperty("wsp.certificate.password"));
	}
	
	@Test
	public void testRequest() throws Exception {
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				assertEquals("echoResponse", result.getLocalName());
				assertEquals(1, result.getChildNodes().getLength());
				assertEquals("structure", result.getChildNodes().item(0).getLocalName());
				
				Action action = serviceClient.getLastResponse().getHeaderElement(Action.class);
				assertEquals("http://provider.poc.saml.itst.dk/Provider/echoResponse", action.getValue());
			}
		});
	}
	
	@Test
	public void responseMustHaveMessageID() throws Exception {
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				assertNotNull(serviceClient.getLastResponse().getMessageID());
			}
		});
	}

	@Test
	public void unsignedTokenShouldFail() throws Exception {
		serviceClient.setToken((Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml")));
		
		try {
			serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
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
		serviceClient.setToken(null);
		try {
			serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void mismatchingCertificatesShouldFail() throws Exception {
		ServiceClient client = new ServiceClient(TestHelper.getCredential());
		client.setToken(token);
		
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
		serviceClient.setSigningPolicy(new SigningPolicy(false));
		try {
			serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void responseMustBeSigned() throws Exception {
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), serviceCredential.getPublicKey(), new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				assertEquals("echoResponse", result.getLocalName());
			}
		});
	}
	
	@Test
	public void tokenWithWrongAudienceMustBeRejected() throws Exception {
		client.setAppliesTo("urn:testing");
		token = client.getToken(null);
		serviceClient.setToken(token);

		try {
			serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurityToken"), ex.getFault().getCode().getValue());			
		}
	}
	

	@Test
	public void expiredTokenMustBeRejected() throws Exception {
		token = client.getToken(null, new DateTime().minusDays(5));
		serviceClient.setToken(token);

		try {
			serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
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
		
		serviceClient.setSigningPolicy(sp);

		try {
			serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
			fail();
		} catch (TrustException e) {
			SOAPException ex = (SOAPException) e.getCause();
			assertEquals(new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurity"), ex.getFault().getCode().getValue());			
		}
	}

	@Test
	public void tokensCanBeReplacedWhenNotProtected() throws Exception {
		serviceClient.setToken(client.getToken(null));
		
		serviceClient.setProtectTokens(false);
		SOAPClientStub soapClient = new SOAPClientStub();
		serviceClient.setSOAPClient(soapClient);
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
		
		Element env = SAMLUtil.loadElementFromString(soapClient.xml);
		NodeList nl = env.getElementsByTagNameNS(TrustConstants.WSSE_NS, "KeyIdentifier");
		for (int i = 0; i < nl.getLength(); i++) {
			Element item = (Element) nl.item(i);
			item.setTextContent(token.getID());
		}
		
		Element a = (Element) env.getElementsByTagNameNS(Assertion.TYPE_NAME.getNamespaceURI(), "Assertion").item(0);
		Node localToken = a.getOwnerDocument().adoptNode(token.getDOM());
		a.getParentNode().replaceChild(localToken, a);
		
		new HttpSOAPClient().wsCall(getProperty("endpoint"), null, null, true, XMLHelper.nodeToString(env), getProperty("action"));
	}
	
	@Test(expected=SOAPException.class)
	public void securityTokenReferenceCannotBeReplaced() throws Exception {
		serviceClient.setToken(client.getToken(null));
		
		serviceClient.setProtectTokens(true);
		SOAPClientStub soapClient = new SOAPClientStub();
		serviceClient.setSOAPClient(soapClient);
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
		
		Element env = SAMLUtil.loadElementFromString(soapClient.xml);
		NodeList nl = env.getElementsByTagNameNS(TrustConstants.WSSE_NS, "KeyIdentifier");
		Element item = (Element) nl.item(nl.getLength() - 1);
		item.setTextContent(token.getID());
		
		Element a = (Element) env.getElementsByTagNameNS(Assertion.TYPE_NAME.getNamespaceURI(), "Assertion").item(0);
		Node localToken = a.getOwnerDocument().adoptNode(token.getDOM());
		a.getParentNode().insertBefore(localToken, a);
		
		new HttpSOAPClient().wsCall(getProperty("endpoint"), null, null, true, XMLHelper.nodeToString(env), getProperty("action"));
	}
	
	@Test
	public void missingFrameworkHeaderShouldFail() throws Exception {
		SOAPClientStub soapClient = new SOAPClientStub();
		serviceClient.setSOAPClient(soapClient);
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
		
		Envelope env = (Envelope) SAMLUtil.unmarshallElementFromString(soapClient.xml);
		env.getHeader().getUnknownXMLObjects().remove(env.getHeader().getUnknownXMLObjects(new QName("urn:liberty:sb:2006-08", "Framework")).get(0));
		
		env.getHeader().getUnknownXMLObjects().remove(SAMLUtil.getFirstElement(env.getHeader(), Security.class));
		
		OIOSoapEnvelope e = new OIOSoapEnvelope(env, true, new SigningPolicy(true));
		e.addSecurityTokenReference(token, Boolean.valueOf(getProperty("protectTokens")));
		e.setTimestamp(5);
		try {
			new HttpSOAPClient().wsCall(getProperty("endpoint"), null, null, true, XMLHelper.nodeToString(e.sign(credential)), getProperty("action"));
		} catch (SOAPException ex) {
			assertNotNull(ex.getFault());
			assertNotNull(ex.getFault().getCode());
			assertEquals(new QName("urn:liberty:sb:2006-08", "FrameworkVersionMismatch"), ex.getFault().getCode().getValue());
		}
	}
	
	@Test
	public void wrongFrameworkHeaderShouldFail() throws Exception {
		SOAPClientStub soapClient = new SOAPClientStub();
		serviceClient.setSOAPClient(soapClient);
		serviceClient.sendRequest(req, getProperty("endpoint"), getProperty("action"), null, null);
		
		Envelope env = (Envelope) SAMLUtil.unmarshallElementFromString(soapClient.xml);
		XSAny framework = (XSAny) env.getHeader().getUnknownXMLObjects(new QName("urn:liberty:sb:2006-08", "Framework")).get(0);
		framework.getUnknownAttributes().put(new QName("version"), "1.0");
		
		env.getHeader().getUnknownXMLObjects().remove(SAMLUtil.getFirstElement(env.getHeader(), Security.class));
		
		OIOSoapEnvelope e = new OIOSoapEnvelope(env, true, new SigningPolicy(true));
		e.addSecurityTokenReference(token, Boolean.valueOf(getProperty("protectTokens")));
		e.setTimestamp(5);
		try {
			new HttpSOAPClient().wsCall(getProperty("endpoint"), null, null, true, XMLHelper.nodeToString(e.sign(credential)), getProperty("action"));
		} catch (SOAPException ex) {
			assertEquals(new QName("urn:liberty:sb:2006-08", "FrameworkVersionMismatch"), ex.getFault().getCode().getValue());
		}
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
