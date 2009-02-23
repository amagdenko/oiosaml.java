package dk.itst.oiosaml.sp.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.servlet.ServletOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.configuration.MapConfiguration;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.SecurityHelper;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.AttributeUtil;

public class TestHelper {

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

	public static void validateUrlSignature(Credential cred, String url, String req, String type) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
//		check the signature
		String signatureAlg = getParameter("SigAlg", url);
		String signature = getParameter("Signature", url);
		assertNotNull(signature);
		assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", URLDecoder.decode(signatureAlg, "UTF-8"));

		String signed = type + "=" + req;
		if (getParameter("RelayState", url) != null) {
			signed += "&RelayState=" + getParameter("RelayState", url);
		}
		signed += "&SigAlg=" + signatureAlg;
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(cred.getPublicKey());
		sig.update(signed.getBytes());
		assertTrue(sig.verify(Base64.decode(URLDecoder.decode(signature, "UTF-8"))));
	}

	public static Document parseBase64Encoded(String req) throws ParserConfigurationException, SAXException, IOException, UnsupportedEncodingException {
		return parseBase64Encoded(req, true);
	}

	public static Document parseBase64Encoded(String req, boolean urlencoded) throws ParserConfigurationException, SAXException, IOException, UnsupportedEncodingException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		InputStream is;
		if(urlencoded) {
			req = URLDecoder.decode(req, "UTF-8");
			is = new InflaterInputStream(new ByteArrayInputStream(Base64.decode(req)), new Inflater(true));
		} else {
			is = new ByteArrayInputStream(Base64.decode(req));
		}
		Document document = builder.parse(is);
		return document;
	}

	public static BasicX509Credential getCredential() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = SecurityHelper.generateKeyPairFromURI("http://www.w3.org/2001/04/xmlenc#rsa-1_5", 512);
        BasicX509Credential credential = new BasicX509Credential();
        credential.setPublicKey(keyPair.getPublic());
        credential.setPrivateKey(keyPair.getPrivate());
		return credential;
	}

	public static String getParameter(String name, String url)  {
		int qpos = url.indexOf('?') + 1;
		String[] parts = url.substring(qpos).split("&");
		for (String part : parts) {
			int pos = part.indexOf('=');
			String key = part.substring(0, pos);
			if (name.equals(key)) {
				return part.substring(pos + 1);
			}
		}
		return null;
	}

	public static String signObject(SignableSAMLObject obj, Credential credential) throws MarshallingException, org.opensaml.xml.signature.SignatureException {
		org.opensaml.xml.signature.Signature signature = SAMLUtil.createSignature("test");
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		obj.setSignature(signature);
		
		Element e = Configuration.getMarshallerFactory().getMarshaller(obj).marshall(obj);
		Signer.signObject(signature);
		
		return XMLHelper.nodeToString(e);
	}
	
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

	public static SPMetadata buildSPMetadata() {
		EntityDescriptor data = (EntityDescriptor) SAMLUtil.unmarshallElement(TestHelper.class.getResourceAsStream("SPMetadata.xml"));
		return new SPMetadata(data, SAMLConstants.SAML20P_NS);
	}

	public static EntityDescriptor buildEntityDescriptor(Credential cred) {
		EntityDescriptor data = (EntityDescriptor) SAMLUtil.unmarshallElement(TestHelper.class.getResourceAsStream("IdPMetadata.xml"));
        IDPSSODescriptor idpSSODescriptor = data.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        
        org.opensaml.xml.signature.X509Certificate cert = SAMLUtil.buildXMLObject(org.opensaml.xml.signature.X509Certificate.class);
        try {
			cert.setValue(Base64.encodeBytes(getCertificate(cred).getEncoded()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
        
		if (idpSSODescriptor.getKeyDescriptors().size() > 0) {
			KeyDescriptor keyDescriptor = (KeyDescriptor) idpSSODescriptor.getKeyDescriptors().get(0);
			if (keyDescriptor.getKeyInfo().getX509Datas().size() > 0) {
				X509Data x509Data = (X509Data) keyDescriptor.getKeyInfo().getX509Datas().get(0);
				x509Data.getX509Certificates().clear();
				x509Data.getX509Certificates().add(cert);
			}
		}
		return data;
	}
	
	public static org.apache.commons.configuration.Configuration buildConfiguration(Map<String, String> props) {
		return new MapConfiguration(props);
	}
	
	public static ServletOutputStream createOutputStream(OutputStream os) {
		return new ByteOutputStream(os);
	}
	
	public static Response buildResponse(Assertion assertion) {
		final Response response = SAMLUtil.buildXMLObject(Response.class);
		response.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		response.getAssertions().add(assertion);
		return response;
	}
	
	private static class ByteOutputStream extends ServletOutputStream {
		private final OutputStream os;
		public ByteOutputStream(OutputStream os) {
			this.os = os;
		}
		public void write(int b) throws IOException {
			os.write(b);
		}
		
	}
}
