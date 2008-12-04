package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;

public class IssueTest extends AbstractTests {
	@Test
	public void testIssue() throws Exception {
		client.getToken(null);
	}
	
	@Test
	public void responseMustBeSigned() throws Exception {
		client.getToken(null);

		assertTrue(client.getLastResponse().isSigned());
		assertTrue(client.getLastResponse().verifySignature(stsCredential.getPublicKey()));
	}
	
	@Test
	public void RSTRMustBeCollection() throws Exception {
		client.getToken(null);
		OIOSoapEnvelope env = client.getLastResponse();
		assertTrue(env.getBody().getClass().toString(), env.getBody() instanceof RequestSecurityTokenResponseCollection);
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
	
	@Test
	public void assertionMustBeSignedCorrectly() throws Exception {
		Element token = client.getToken(null);
		OIOAssertion assertion = getAssertion(token);
		
		assertTrue(assertion.verifySignature(stsCredential.getPublicKey()));
	}
	
	private OIOAssertion getAssertion(Element e) {
		return new OIOAssertion((Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(e)));
	}
}
