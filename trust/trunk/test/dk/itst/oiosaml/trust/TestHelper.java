package dk.itst.oiosaml.trust;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.AttributeUtil;

public class TestHelper {

	public static Assertion buildAssertion(String recipient, String audience) {
		Assertion assertion = SAMLUtil.buildXMLObject(Assertion.class);
		assertion.setID(Utils.generateUUID());
		assertion.setSubject(SAMLUtil.createSubject("joetest", recipient, new DateTime().plusHours(1)));
		assertion.setIssueInstant(new DateTime());
		assertion.setIssuer(SAMLUtil.createIssuer("idp1.test.oio.dk"));
		
		assertion.setConditions(SAMLUtil.createAudienceCondition(audience));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plus(10000));

		AuthnContext context = SAMLUtil.createAuthnContext("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
		AuthnStatement authnStatement = SAMLUtil.buildXMLObject(AuthnStatement.class);
		authnStatement.setAuthnContext(context);
		authnStatement.setAuthnInstant(new DateTime());
		authnStatement.setSessionIndex(Utils.generateUUID());
		assertion.getAuthnStatements().add(authnStatement);
		
		AttributeStatement as = SAMLUtil.buildXMLObject(AttributeStatement.class);
		as.getAttributes().add(AttributeUtil.createAssuranceLevel(2));
		assertion.getAttributeStatements().add(as);
		
		return assertion;
	}
}
