package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;

public class SecurityTokenReferenceTest extends TrustTests {

	private SecurityTokenReference str;

	@Before
	public void setUp() {
		str = generateReference();
	}
	
	@Test
	public void testSecurityTokenReference() {
		assertEquals("type", str.getTokenType());
		assertNotNull(str.getKeyIdentifier());
		assertEquals("id", str.getKeyIdentifier().getTextContent());
	}
	
	@Test
	public void testMarshall() {
		Element e = SAMLUtil.marshallObject(str);
		assertNotNull(e);
		assertEquals(TrustConstants.WSSE_NS, e.getNamespaceURI());
		assertEquals("SecurityTokenReference", e.getLocalName());
	}
	
	@Test
	public void testUnmarshall() {
		String xml = "<wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\" wsu:Id=\"uuid_3f60b21c-9066-4e7a-8319-4ab643d63c6a\" wsse11:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\"><wsse:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\">iBPX3s0GM_CSzjKhmaDrtB_yyrJQ</wsse:KeyIdentifier></wsse:SecurityTokenReference>";
		SecurityTokenReference ref = (SecurityTokenReference) SAMLUtil.unmarshallElementFromString(xml);
		assertNotNull(ref);
		assertEquals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", ref.getTokenType());
		assertNotNull(ref.getKeyIdentifier());
	}
	
	private SecurityTokenReference generateReference() {
		SecurityTokenReference str = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		str.setTokenType("type");
		KeyIdentifier ki = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		ki.setTextContent("id");
		str.setKeyIdentifier(ki);
		
		return str;
	}
}
