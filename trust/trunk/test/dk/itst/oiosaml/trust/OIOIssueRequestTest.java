package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wstrust.RequestSecurityToken;


public class OIOIssueRequestTest extends TrustTests {
	
	private OIOIssueRequest req;

	@Before
	public void setUp() {
		req = OIOIssueRequest.buildRequest();
	}
	
	@Test
	public void testBuild() {
		assertNotNull(req.getXMLObject());
		assertEquals(2, req.getXMLObject().getOrderedChildren().size());
		assertTrue(req.getXMLObject() instanceof RequestSecurityToken);
	}
	
	@Test
	public void testIssuer() {
		req.setIssuer("issuer");
		
		RequestSecurityToken rst = (RequestSecurityToken) req.getXMLObject();
		assertNotNull(rst.getIssuer());
		assertEquals("issuer", rst.getIssuer().getAddress().getValue());
	}
	
	@Test
	public void testAppliesTo() {
		assertNull(((RequestSecurityToken)req.getXMLObject()).getAppliesTo());
		
		req.setAppliesTo("appliesto");
		RequestSecurityToken rst = (RequestSecurityToken) req.getXMLObject();
		assertNotNull(rst.getAppliesTo());
		EndpointReference epr = (EndpointReference) rst.getAppliesTo().getUnknownXMLObjects().get(0);
		assertEquals("appliesto", epr.getAddress().getValue());
	}
	
	@Test
	public void testOnBehalfOf() {
		assertNull(((RequestSecurityToken)req.getXMLObject()).getOnBehalfOf());
		
		req.setOnBehalfOf("id");
		RequestSecurityToken rst = (RequestSecurityToken) req.getXMLObject();
		assertNotNull(rst.getOnBehalfOf());
		assertNotNull(rst.getOnBehalfOf().getSecurityTokenReference());
		assertNull(rst.getOnBehalfOf().getEndpointReference());
		assertEquals(TrustConstants.TOKEN_TYPE_SAML_20, rst.getOnBehalfOf().getSecurityTokenReference().getTokenType());
		assertEquals("id", rst.getOnBehalfOf().getSecurityTokenReference().getKeyIdentifier().getValue());
	}
}
