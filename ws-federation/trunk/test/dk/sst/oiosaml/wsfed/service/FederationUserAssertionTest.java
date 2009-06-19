package dk.sst.oiosaml.wsfed.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.util.AttributeUtil;
import dk.itst.oiosaml.trust.TrustBootstrap;

public class FederationUserAssertionTest {

	@BeforeClass
	public static void init() {
		TrustBootstrap.bootstrap();
	}

	private Assertion a;
	
	@Before
	public void setup() {
		a = SAMLUtil.buildXMLObject(Assertion.class);
	}
	
	@Test
	public void testEmptyAttribute() throws Exception {
		FederationUserAssertionImpl ua = getAssertion();
		
		assertNotNull("empty attributes should be supported", ua.getRoles());
		assertEquals(0, ua.getRoles().size());
	}

	
	@Test
	public void testRoles() {
		AttributeStatement as = SAMLUtil.buildXMLObject(AttributeStatement.class);
		Attribute attr = AttributeUtil.createAttribute(WSFedConstants.ATTRIBUTE_ROLES, "roles", "");
		attr.getAttributeValues().add(AttributeUtil.createAttributeValue("value1"));
		attr.getAttributeValues().add(AttributeUtil.createAttributeValue("value2"));
		as.getAttributes().add(attr);
		a.getAttributeStatements().add(as);
		
		FederationUserAssertionImpl ua = getAssertion();
		assertNotNull(ua.getRoles());
		assertEquals(2, ua.getRoles().size());
	}
	
	@Test
	public void testUserPrincipalName() {
		assertNull("null attribute must be supported", getAssertion().getUserPrincipalName());
		
		AttributeStatement as = SAMLUtil.buildXMLObject(AttributeStatement.class);
		Attribute attr = AttributeUtil.createAttribute(WSFedConstants.ATTRIBUTE_UPN, "upn", "");
		attr.getAttributeValues().add(AttributeUtil.createAttributeValue("value1"));
		as.getAttributes().add(attr);
		a.getAttributeStatements().add(as);
		
		FederationUserAssertionImpl ua = getAssertion();
		assertNotNull(ua.getRoles());
		assertEquals("value1", ua.getUserPrincipalName());
		
	}
	
	private FederationUserAssertionImpl getAssertion() {
		FederationUserAssertionImpl ua = new FederationUserAssertionImpl(new OIOAssertion(a));
		return ua;
	}
}
