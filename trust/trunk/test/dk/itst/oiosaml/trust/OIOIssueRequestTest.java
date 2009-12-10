package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wstrust.Claims;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.OnBehalfOf;
import org.opensaml.ws.wstrust.RequestSecurityToken;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.ClaimType;


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
		Issuer issuer = SAMLUtil.getFirstElement(rst, Issuer.class);
		assertNotNull(issuer);
		assertEquals("issuer", issuer.getAddress().getValue());
	}
	
	@Test
	public void testAppliesTo() {
		assertNull(SAMLUtil.getFirstElement(((RequestSecurityToken)req.getXMLObject()), AppliesTo.class));
		
		req.setAppliesTo("appliesto");
		RequestSecurityToken rst = (RequestSecurityToken) req.getXMLObject();
		
		AppliesTo appliesTo = SAMLUtil.getFirstElement(rst, AppliesTo.class);
		assertNotNull(appliesTo);
		EndpointReference epr = (EndpointReference) appliesTo.getUnknownXMLObjects().get(0);
		assertEquals("appliesto", epr.getAddress().getValue());
	}
	
	@Test
	public void testOnBehalfOf() {
		assertNull(SAMLUtil.getFirstElement(((RequestSecurityToken)req.getXMLObject()), OnBehalfOf.class));
		
		req.setOnBehalfOf("id");
		RequestSecurityToken rst = (RequestSecurityToken) req.getXMLObject();
		OnBehalfOf onBehalfOf = SAMLUtil.getFirstElement(rst, OnBehalfOf.class);
		assertNotNull(onBehalfOf);
		assertTrue(onBehalfOf.getUnknownXMLObject() instanceof SecurityTokenReference);
		SecurityTokenReference str = (SecurityTokenReference) onBehalfOf.getUnknownXMLObject();
		assertEquals(TrustConstants.TOKEN_TYPE_SAML_20, str.getUnknownAttributes().get(TrustConstants.TOKEN_TYPE));
		assertEquals("id", SAMLUtil.getFirstElement(str, KeyIdentifier.class).getValue());
	}
	
	@Test
	public void testClaims() {
		RequestSecurityToken rst = (RequestSecurityToken) req.getXMLObject();
		assertNull(SAMLUtil.getFirstElement(rst, Claims.class));
		
		req.setClaims("urn:dialect", "urn:claim1", "urn:claim2");
		
		Claims claims = SAMLUtil.getFirstElement(rst, Claims.class);
		assertNotNull(claims);
		assertEquals("urn:dialect", claims.getDialect());
		assertEquals(2, claims.getUnknownXMLObjects().size());
		
		assertEquals("urn:claim1", SAMLUtil.getFirstElement(claims, ClaimType.class).getUri());
	}
}
