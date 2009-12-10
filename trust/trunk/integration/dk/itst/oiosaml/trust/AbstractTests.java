package dk.itst.oiosaml.trust;

import java.io.IOException;
import java.util.Properties;

import org.joda.time.DateTime;
import org.junit.Before;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wsaddressing.Metadata;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.sp.model.OIOAssertion;

public class AbstractTests extends TrustTests {

	protected EndpointReference epr;
	protected BasicX509Credential credential;
	protected Assertion assertion;
	protected BasicX509Credential stsCredential;
	protected TrustClient client;
	
	@Before
	public final void setUpTest() throws Exception {
		credential = credentialRepository.getCredential(getProperty("wsc.certificate"), getProperty("wsc.certificate.password"));
		assertion = (Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
		epr = SAMLUtil.buildXMLObject(EndpointReference.class);
		
		Address address = SAMLUtil.buildXMLObject(Address.class);
		address.setValue(getProperty("sts"));
		epr.setAddress(address);
		
		Metadata md = SAMLUtil.buildXMLObject(Metadata.class);
		epr.setMetadata(md);

		SecurityContext ctx = SAMLUtil.buildXMLObject(SecurityContext.class);
		md.getUnknownXMLObjects().add(ctx);

		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).setAudienceURI("tri-test1.trifork.com");
		assertion.setSignature(null);
		new OIOAssertion(assertion).sign(credential);
		
		Token token = new Token();
		token.setUsage("urn:liberty:security:tokenusage:2006-08:SecurityToken");
		ctx.getTokens().add(token);
		token.setAssertion(assertion);

		stsCredential = credentialRepository.getCredential(getProperty("sts.certificate"), getProperty("sts.certificate.password"));
		client = new TrustClient(epr, credential, stsCredential.getPublicKey());
		client.setAppliesTo(getProperty("endpoint"));
		client.setUseReferenceForDelegateToken(false);
		client.setUseActAs(true);
	}

	protected String getProperty(String name) {
		Properties p = new Properties();
		try {
			p.load(getClass().getResourceAsStream("/test.properties"));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return p.getProperty(name);
	}

}
