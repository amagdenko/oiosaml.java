package dk.itst.oiosaml.poc;

import java.util.Collections;
import java.util.GregorianCalendar;

import liberty.sb._2006_08.Framework;

import com.sun.xml.ws.api.security.trust.client.STSIssuedTokenConfiguration;
import com.sun.xml.ws.security.Token;
import com.sun.xml.ws.security.trust.STSIssuedTokenFeature;
import com.sun.xml.ws.security.trust.impl.client.DefaultSTSIssuedTokenConfiguration;
import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.AttributeStatement;
import com.sun.xml.wss.saml.AudienceRestriction;
import com.sun.xml.wss.saml.Conditions;
import com.sun.xml.wss.saml.NameID;
import com.sun.xml.wss.saml.SAMLAssertionFactory;
import com.sun.xml.wss.saml.Subject;

import dk.itst.saml.poc.provider.Echo;
import dk.itst.saml.poc.provider.EchoResponse;
import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;

public class Client {

	public static void main(String[] args) {
        try { // Call Web Service Operation
        	System.out.println("Client.main()");
        	DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration();
			config.setSTSInfo("http://docs.oasis-open.org/ws-sx/ws-trust/200512", 
					"http://localhost:8080/sts/sts", 
					"http://localhost:8080/sts/sts?wsdl", 
					"SecurityTokenService", 
					"ISecurityTokenService_Port", 
					"http://tempuri.org/");
        	config.getOtherOptions().put(STSIssuedTokenConfiguration.ACT_AS, createToken());
        	
			STSIssuedTokenFeature feature = new STSIssuedTokenFeature(config);
            ProviderService service = new ProviderService();
            Provider port = service.getProviderPort(feature);
            
            Framework f = new Framework();
            f.setMustUnderstand("true");
            f.setProfile("urn:liberty:sb:profile:basic");
            f.setVersion("2.0");
			EchoResponse result = port.echo(new Echo(), f);
            System.out.println("Result = "+result);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

	}
	
	private static Token createToken() {
		try {

			SAMLAssertionFactory saf = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML2_0);
			NameID issuer = saf.createNameID("http://jre-mac.trifork.com", null, null);

			Subject subj = saf.createSubject(saf.createNameID("fissirul", null, null), saf.createSubjectConfirmation(null, "urn:oasis:names:tc:SAML:2.0:cm:bearer"));
			AudienceRestriction ar = saf.createAudienceRestriction(Collections.singletonList("jre-mac.trifork.com"));
			Conditions conditions = saf.createConditions(new GregorianCalendar(), new GregorianCalendar(), null, Collections.singletonList(ar), null, null);

			AttributeStatement statement = saf.createAttributeStatement(Collections.singletonList(saf.createAttribute("urn:test", Collections.singletonList("test"))));
			Assertion assertion = saf.createAssertion(null, issuer, new GregorianCalendar(), conditions, null, subj, Collections.singletonList(statement));

			return assertion;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
