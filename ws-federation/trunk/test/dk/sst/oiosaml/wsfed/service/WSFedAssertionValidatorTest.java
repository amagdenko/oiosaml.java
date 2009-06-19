package dk.sst.oiosaml.wsfed.service;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthzDecisionStatement;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.ValidationException;

public class WSFedAssertionValidatorTest extends AbstractTests {

	private OIOAssertion oio;
	private Assertion a;
	private WSFedAssertionValidator v;

	@Before
	public void setup() {
		a = (Assertion) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
		a.getConditions().setNotOnOrAfter(new DateTime().plusMinutes(5));
		oio = new OIOAssertion(a);
		v = new WSFedAssertionValidator();
	}
	
	@Test
	public void testValidate() {
		validate();
	}
	
	@Test(expected=ValidationException.class)
	public void testAuthnStatements() {
		a.getAuthnStatements().clear();
		
		validate();
	}
	
	@Test(expected=ValidationException.class)
	public void testNoAttributeStatements() {
		a.getAttributeStatements().clear();
		validate();
	}
	
	@Test(expected=ValidationException.class)
	public void testMoreAttributeStatements() {
		a.getAttributeStatements().add(SAMLUtil.buildXMLObject(AttributeStatement.class));
		validate();
	}
	
	@Test(expected=ValidationException.class)
	public void testAuthzStatements() {
		a.getAuthzDecisionStatements().add(SAMLUtil.buildXMLObject(AuthzDecisionStatement.class));
		
		validate();
	}
	
	private void validate() {
		v.validate(oio, rc.getSpMetadata().getEntityID(), rc.getSpMetadata().getAssertionConsumerServiceLocation(0));
	}
}
