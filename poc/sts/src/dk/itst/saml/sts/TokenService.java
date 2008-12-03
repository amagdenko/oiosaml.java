package dk.itst.saml.sts;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wssecurity.BinarySecurityToken;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestedAttachedReference;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.ws.wstrust.RequestedUnattachedReference;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.NameIDFormat;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.trust.OIOSoapEnvelope;
import dk.itst.oiosaml.trust.SigningPolicy;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustConstants;

public class TokenService extends HttpServlet {
	private static CredentialRepository credentialRepository = new CredentialRepository();
	
	private static final Logger log = Logger.getLogger(TokenService.class);

	private Configuration cfg;
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
		
		SAMLConfiguration.setConfigurationName("sts");
		SAMLConfiguration.setHomeProperty(null);
		cfg = SAMLConfiguration.getSystemConfiguration();
		
		log.info("Configured OIOSAML to " + System.getProperty("user.home") + "/.oiosaml/sts.properties");
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		BasicX509Credential credential = credentialRepository.getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(cfg, "sts.certificate.location"), cfg.getString("sts.certificate.password"));

		String xml = IOUtils.toString(req.getInputStream());
		log.debug("Received request: " + xml);
		
		OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(xml));
		BinarySecurityToken bst = SAMLUtil.getFirstElement(env.getHeaderElement(Security.class), BinarySecurityToken.class);
		
		RequestSecurityToken rst = (RequestSecurityToken) env.getBody();
		Assertion bootstrapAssertion = SAMLUtil.getFirstElement(rst.getOnBehalfOf(), Assertion.class);
		OIOAssertion bootstrap = null;
		if (bootstrapAssertion != null) {
			bootstrap = new OIOAssertion(bootstrapAssertion);
		} else {
			log.error("No SAML Assertion in OnBehalfOf");
		}
		
		
		OIOSoapEnvelope res = OIOSoapEnvelope.buildResponse(new SigningPolicy(true), env);
		
		RequestSecurityTokenResponseCollection rstrc = SAMLUtil.buildXMLObject(RequestSecurityTokenResponseCollection.class);
		RequestSecurityTokenResponse rstr = SAMLUtil.buildXMLObject(RequestSecurityTokenResponse.class);
		rstrc.getRequestSecurityTokenResponses().add(rstr);
		
		rstr.setAppliesTo(SAMLUtil.clone(rst.getAppliesTo()));
		rstr.setContext(rst.getContext());
		
		Issuer issuer = SAMLUtil.buildXMLObject(Issuer.class);
		Address address = SAMLUtil.buildXMLObject(Address.class);
		address.setValue(req.getRequestURL().toString());
		issuer.setAddress(address);
		rstr.setIssuer(issuer);
		
		rstr.setTokenType(SAMLUtil.buildXMLObject(TokenType.class));
		rstr.getTokenType().setValue(TrustConstants.TOKEN_TYPE_SAML_20);
		
		RequestedSecurityToken requestedSecurityToken = SAMLUtil.buildXMLObject(RequestedSecurityToken.class);
		rstr.setRequestedSecurityToken(requestedSecurityToken);
		Assertion assertion = generateAssertion(req, bootstrap, "urn:to", bst.getValue(), credential);
		requestedSecurityToken.getUnknownXMLObjects().add(assertion);
		
		RequestedAttachedReference attached = SAMLUtil.buildXMLObject(RequestedAttachedReference.class);
		SecurityTokenReference tokenReference = generateTokenReference(assertion);
		attached.setSecurityTokenReference(tokenReference);
		rstr.setRequestedAttachedReference(attached);
		
		rstr.setRequestedUnattachedReference(SAMLUtil.buildXMLObject(RequestedUnattachedReference.class));
		rstr.getRequestedUnattachedReference().setSecurityTokenReference(SAMLUtil.clone(tokenReference));
		
		
		res.setBody(rstrc);
		res.setTimestamp(5);
		res.setAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal");
		res.setTo("http://www.w3.org/2005/08/addressing/anonymous");
		
		try {
			xml = XMLHelper.nodeToString(res.sign(credential));
			resp.setContentType("text/xml; charset=utf-8");
			resp.setContentLength(xml.length());
			IOUtils.write(xml, resp.getOutputStream());
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private SecurityTokenReference generateTokenReference(Assertion assertion) {
		SecurityTokenReference tokenReference = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		KeyIdentifier keyIdentifier = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		keyIdentifier.setValue(assertion.getID());
		keyIdentifier.setValueType(TrustConstants.SAMLID);
		keyIdentifier.setEncodingType(null);
		tokenReference.setKeyIdentifier(keyIdentifier);
		return tokenReference;
	}

	private Assertion generateAssertion(HttpServletRequest req, OIOAssertion bootstrap, String to, String x509, BasicX509Credential credential) {
		Assertion a = SAMLUtil.buildXMLObject(Assertion.class);
		a.setID(Utils.generateUUID());
		a.setIssueInstant(new DateTime(DateTimeZone.UTC));
		
		a.setIssuer(SAMLUtil.createIssuer(cfg.getString("sts.entityId")));
		Subject subject = SAMLUtil.buildXMLObject(Subject.class);
		
		if (bootstrap != null) {
			subject.setNameID(SAMLUtil.clone(bootstrap.getAssertion().getSubject().getNameID()));
		}
		
		SubjectConfirmation confirmation = SAMLUtil.buildXMLObject(SubjectConfirmation.class);
		confirmation.setMethod(OIOSAMLConstants.METHOD_HOK);
		confirmation.setNameID(SAMLUtil.createNameID(req.getRequestURL().toString()));
		confirmation.getNameID().setFormat(NameIDFormat.ENTITY.getFormat());
		
		SubjectConfirmationData data = SAMLUtil.buildXMLObject(SubjectConfirmationData.class);
		data.getUnknownAttributes().put(new QName("http://www.w3.org/2001/XMLSchema-instance", "type"), "saml:KeyInfoConfirmationDataType");
		
		KeyInfo keyInfo = SAMLUtil.buildXMLObject(KeyInfo.class);
		X509Data x509data = SAMLUtil.buildXMLObject(X509Data.class);
		X509Certificate cert = SAMLUtil.buildXMLObject(X509Certificate.class);
		cert.setValue(x509);
		x509data.getX509Certificates().add(cert);
		keyInfo.getX509Datas().add(x509data);
		data.getUnknownXMLObjects().add(keyInfo);
		confirmation.setSubjectConfirmationData(data);
		
		subject.getSubjectConfirmations().add(confirmation);
		a.setSubject(subject);
		
		a.setConditions(SAMLUtil.createAudienceCondition(to));
		
		if (bootstrap != null) {
			a.getAttributeStatements().add(SAMLUtil.clone(bootstrap.getAssertion().getAttributeStatements().get(0)));
		}
		
		OIOAssertion oa = new OIOAssertion(SAMLUtil.clone(a));
		oa.sign(credential);
		
		return oa.getAssertion();
	}

}
