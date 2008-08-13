package dk.itst.saml.poc;

import java.math.BigInteger;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;

import javax.xml.ws.BindingProvider;

import org.w3c.dom.Element;

import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.Attribute;
import com.sun.xml.wss.saml.AttributeStatement;
import com.sun.xml.wss.saml.Conditions;
import com.sun.xml.wss.saml.NameIdentifier;
import com.sun.xml.wss.saml.SAMLAssertionFactory;
import com.sun.xml.wss.saml.Subject;
import com.sun.xml.wss.saml.SubjectConfirmation;

import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;

public class ProviderClient {

	public static void main(String[] args) {
		AssertionHolder.set(createAssertion());
		Provider port = new ProviderService().getProviderPort();
		((BindingProvider)port).getRequestContext().put("test", "test");
		System.out.println(port.echo());
	}
	
	private static Element createAssertion() {
        Assertion assertion = null;
        try {
            // create the assertion id
            String assertionID = String.valueOf(System.currentTimeMillis());
            String issuer = "http://trifork.com";
            
            
            GregorianCalendar c = new GregorianCalendar();
            long beforeTime = c.getTimeInMillis();
            // roll the time by one hour
            long offsetHours = 60*60*1000;

            c.setTimeInMillis(beforeTime - offsetHours);
            GregorianCalendar before= (GregorianCalendar)c.clone();
            
            c = new GregorianCalendar();
            long afterTime = c.getTimeInMillis();
            c.setTimeInMillis(afterTime + offsetHours);
            GregorianCalendar after = (GregorianCalendar)c.clone();
            
            GregorianCalendar issueInstant = new GregorianCalendar();
            // statements


            SAMLAssertionFactory factory = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML2_0);

            NameIdentifier nmId =
            factory.createNameIdentifier("CN=SAML User,OU=SU,O=SAML User,L=Los Angeles,ST=CA,C=US",
            null, // not sure abt this value
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");

            SubjectConfirmation scf =
            factory.createSubjectConfirmation("urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");
           
 
            Subject subj = factory.createSubject(nmId, scf);
           
            List<Attribute> attributes = new LinkedList<Attribute>();

            attributes.add( factory.createAttribute(
                "attribute1",
                "urn:com:sun:xml:wss:attribute",
                 Collections.singletonList("attribute1")));

            AttributeStatement attributeStatement = factory.createAttributeStatement(attributes);
            
            Conditions conditions = factory.createConditions(before, after, null, null, null);
            
            assertion = factory.createAssertion(assertionID, factory.createNameID(issuer, null, null), issueInstant,
            conditions, null, subj, Collections.singletonList(attributeStatement));
            assertion.setMajorVersion(BigInteger.valueOf(2));
            assertion.setMinorVersion(BigInteger.ZERO);
            return assertion.toElement(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

	}
}
