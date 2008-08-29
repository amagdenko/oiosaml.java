package dk.itst.oiosaml.trust;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.AttributeUtil;
import dk.itst.oiosaml.sp.util.SecurityHelper;

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
	
	public static BasicX509Credential getCredential() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, InvalidKeyException, SignatureException {
        KeyPair keyPair = SecurityHelper.generateKeyPairFromURI("http://www.w3.org/2001/04/xmlenc#rsa-1_5", 512);
        BasicX509Credential credential = new BasicX509Credential();
        credential.setPublicKey(keyPair.getPublic());
        credential.setPrivateKey(keyPair.getPrivate());
        credential.setEntityCertificate(getCertificate(credential));
		return credential;
	}

	public static X509Certificate getCertificate(Credential cred) throws CertificateEncodingException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		X509V1CertificateGenerator gen = new X509V1CertificateGenerator();
		gen.setSerialNumber(BigInteger.valueOf(34234));
		gen.setIssuerDN(new X509Principal("C=DK, O=test, OU=test"));
		gen.setNotAfter(new Date(System.currentTimeMillis() + 100000L));
		gen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
		gen.setSubjectDN(new X509Principal("C=DK, O=test, OU=test"));
		gen.setPublicKey(cred.getPublicKey());
		gen.setSignatureAlgorithm("SHA1WithRSA");
		X509Certificate cert = gen.generate(cred.getPrivateKey());
		return cert;
	}
}
