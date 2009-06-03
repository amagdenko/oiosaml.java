package dk.sst.oiosaml.wsfed.service;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.model.validation.BasicAssertionValidator;
import dk.itst.oiosaml.sp.model.validation.ValidationException;

public class WSFedAssertionValidator extends BasicAssertionValidator implements AssertionValidator {

	public void validate(OIOAssertion assertion, String spEntityId, String spAssertionConsumerURL) throws ValidationException {
		super.validate(assertion, spEntityId, spAssertionConsumerURL);
		
		Assertion a = assertion.getAssertion();
		
		DateTime confirmationTime = assertion.getConfirmationTime();
		if (confirmationTime == null || !confirmationTime.isAfterNow()) {
			throw new ValidationException("Subject Confirmation Data is expired: " + confirmationTime + " before " + new DateTime());
		}

    	// There must be only be one AuthnStatement within the assertion
    	if (a.getAuthnStatements().size() != 1) {  
    		throw new ValidationException("The assertion must contain exactly one AuthnStatement. Was " + a.getAuthnStatements().size());
    	}
    	
    	// There must be exactly one AttributeStatement within the assertion
    	if (a.getAttributeStatements().size() != 1) {  
    		throw new ValidationException("The assertion must contain exactly one AttributeStatement. Contains " + a.getAttributeStatements().size());
    	}
    	// There must not be a AuthzDecisionStatement within the assertion
    	if (a.getAuthzDecisionStatements().size() != 0) {  
    		throw new ValidationException("The assertion must not contain a AuthzDecisionStatement. Contains " + a.getAuthzDecisionStatements().size());
    	}
	}

}
