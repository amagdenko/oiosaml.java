package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;

public class RequestedSecurityTokenTest extends TrustTests {

	private RequestedSecurityToken token;


	@Before
	public void setUp() {
		token = generateToken();
	}
	
	@Test
	public void testRequestedSecurityToken() {
		assertEquals(1, token.getAssertions().size());
	}
	
	@Test
	public void testMarshall() {
		Element e = SAMLUtil.marshallObject(token);
		assertNotNull(e);
		assertEquals(TrustConstants.WST_NS, e.getNamespaceURI());
		assertEquals("RequestedSecurityToken", e.getLocalName());
		assertEquals(1, e.getElementsByTagNameNS(SAMLConstants.SAML20_NS, "Assertion").getLength());
	}
	
	@Test
	public void testUnmarshall() {
		String xml = "<RequestedSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/\"><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"></Assertion></RequestedSecurityToken>";
		RequestedSecurityToken token = (RequestedSecurityToken) SAMLUtil.unmarshallElementFromString(xml);
		assertNotNull(token);
		assertEquals(1, token.getAssertions().size());
	}
	
	
	private RequestedSecurityToken generateToken() {
		RequestedSecurityToken t = SAMLUtil.buildXMLObject(RequestedSecurityToken.class);
		
		Assertion assertion = TestHelper.buildAssertion("recipient", "audience");
		t.getAssertions().add(assertion);
		
		return t;
	}
}
