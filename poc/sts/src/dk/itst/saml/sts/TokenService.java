package dk.itst.saml.sts;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.io.IOUtils;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wssecurity.BinarySecurityToken;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.NameIDFormat;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.trust.OIOSoapEnvelope;
import dk.itst.oiosaml.trust.SigningPolicy;
import dk.itst.oiosaml.trust.TrustBootstrap;

public class TokenService extends HttpServlet {
	private static CredentialRepository credentialRepository = new CredentialRepository();
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		BasicX509Credential credential = credentialRepository.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234");

		String xml = IOUtils.toString(req.getInputStream());
		
		
		OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(xml));
		BinarySecurityToken bst = SAMLUtil.getFirstElement(env.getHeaderElement(Security.class), BinarySecurityToken.class);
		
		RequestSecurityToken rst = (RequestSecurityToken) env.getBody();
		OIOAssertion bootstrap = new OIOAssertion(SAMLUtil.getFirstElement(rst.getOnBehalfOf(), Assertion.class));
		
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
		
		rstr.setRequestType(SAMLUtil.clone(rst.getRequestType()));
		rstr.setTokenType(SAMLUtil.clone(rst.getTokenType()));
		
		RequestedSecurityToken requestedSecurityToken = SAMLUtil.buildXMLObject(RequestedSecurityToken.class);
		rstr.setRequestedSecurityToken(requestedSecurityToken);
		requestedSecurityToken.getUnknownXMLObjects().add(generateAssertion(req, bootstrap, "urn:to", bst.getValue(), credential));
		
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

	private Assertion generateAssertion(HttpServletRequest req, OIOAssertion bootstrap, String to, String x509, BasicX509Credential credential) {
		Assertion a = SAMLUtil.buildXMLObject(Assertion.class);
		a.setID(Utils.generateUUID());
		
		a.setIssuer(SAMLUtil.createIssuer(req.getRequestURL().toString()));
		Subject subject = SAMLUtil.buildXMLObject(Subject.class);
		
		subject.setNameID(SAMLUtil.clone(bootstrap.getAssertion().getSubject().getNameID()));
		
		SubjectConfirmation confirmation = SAMLUtil.buildXMLObject(SubjectConfirmation.class);
		confirmation.setMethod(OIOSAMLConstants.METHOD_HOK);
		confirmation.setNameID(SAMLUtil.createNameID(req.getRequestURL().toString()));
		confirmation.getNameID().setFormat(NameIDFormat.ENTITY.getFormat());
		
		SubjectConfirmationData data = SAMLUtil.buildXMLObject(SubjectConfirmationData.class);
		data.setRecipient(to);
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
		
		OIOAssertion oa = new OIOAssertion(SAMLUtil.clone(a));
		oa.sign(credential);
		
		return oa.getAssertion();
	}

}
