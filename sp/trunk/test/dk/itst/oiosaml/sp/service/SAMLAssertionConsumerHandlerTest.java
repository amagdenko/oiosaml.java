package dk.itst.oiosaml.sp.service;

import static dk.itst.oiosaml.sp.service.TestHelper.buildAssertion;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.Configuration;
import org.hamcrest.Description;
import org.jmock.Expectations;
import org.jmock.api.Action;
import org.jmock.api.Invocation;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.OIOSAMLConstants;
import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.AuthenticationHandler;
import dk.itst.oiosaml.sp.PassiveUserAssertion;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.model.validation.OIOSAMLAssertionValidator;
import dk.itst.oiosaml.sp.service.session.Request;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.LogId;
import dk.itst.oiosaml.sp.service.util.SOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

public class SAMLAssertionConsumerHandlerTest extends AbstractServiceTests {

	private SAMLAssertionConsumerHandler sh;
	private Configuration configuration;
	private RequestContext ctx;
	private HashMap<String, String> conf;

	@SuppressWarnings("serial")
	@Before
	public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, InvalidKeyException, SignatureException {
		ids = new HashMap<String, LogId>();
		context.checking(new Expectations() {{
			allowing(req).getRequestURI(); will(returnValue("http://test"));
			allowing(req).getQueryString(); will(returnValue(""));
		}});
		sh = new SAMLAssertionConsumerHandler(new OIOSAMLAssertionValidator());
		conf = new HashMap<String, String>() {{
			put(Constants.PROP_IGNORE_CERTPATH, "false");
		}};
		configuration = TestHelper.buildConfiguration(conf);
		ctx = new RequestContext(req, res, idpMetadata, spMetadata, credential, configuration, logUtil, handler);
	}
	
	@Test
	public void failWhenMissingSAMLart() throws IOException, ServletException {
		context.checking(new Expectations() {{
			allowing(req).getParameter(with(any(String.class))); will(returnValue(null));
		}});
		try {
			sh.handleGet(ctx);
			fail("SAMLArt not set");
		} catch (IllegalArgumentException e) {}
	}
	
	@Test
	public void failWhenResponseIsUnsigned() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(null));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(Utils.generateUUID()));

			one(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(aNull(String.class)), with(aNull(String.class)), with(any(Boolean.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), false, false, null);
				}
			});
		}});
		sh.setSoapClient(client);
		
		try {
			sh.handleGet(ctx);
			fail("Response is not signed");
		} catch (RuntimeException e) {}
		
		
	}
	
	@Test
	public void testResolveSuccess() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);

		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(null));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(handler.saveRequest(new Request("requesturi", "query", "GET", new HashMap<String, String[]>()))));
			one(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(aNull(String.class)), with(aNull(String.class)), with(any(Boolean.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), true, false, null);
				}
			});
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
			one(res).sendRedirect("requesturi?query");
		}});
		sh.setSoapClient(client);
		
		sh.handleGet(ctx);
	}
	
	@Test
	public void testPost() throws Exception {
		String id = Utils.generateUUID();
		handler.registerRequest(id, idpEntityId);
		ArtifactResponse r = (ArtifactResponse) buildResponse(Utils.generateUUID(), true, false, id).getBody().getUnknownXMLObjects().get(0);
		final String response = Base64.encodeBytes(XMLHelper.nodeToString(SAMLUtil.marshallObject(r.getMessage())).getBytes());
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(response));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(handler.saveRequest(new Request("requesturi", "query", "GET", new HashMap<String, String[]>()))));
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
			one(res).sendRedirect("requesturi?query");
		}});
		
		sh.handlePost(ctx);
	}
	
	@Test
	public void testPassive() throws Exception {
		final ByteArrayOutputStream bos = generateArtifact();
		final SOAPClient client = context.mock(SOAPClient.class);

		conf.put(Constants.PROP_PASSIVE, "true");
		conf.put(Constants.PROP_PASSIVE_USER_ID, "passive");
		final String reqId = Utils.generateUUID();
		handler.registerRequest(reqId, idpEntityId);
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLART); will(returnValue(Base64.encodeBytes(bos.toByteArray())));
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(null));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(handler.saveRequest(new Request("requesturi", "query", "GET", new HashMap<String, String[]>()))));
			one(client).wsCall(with(any(XMLObject.class)), with(any(LogUtil.class)), with(equal(idpMetadata.getMetadata("idp1.test.oio.dk").getArtifactResolutionServiceLocation(SAMLConstants.SAML2_SOAP11_BINDING_URI))), with(aNull(String.class)), with(aNull(String.class)), with(any(Boolean.class)));
			will(new Action() {
				public void describeTo(Description description) {}

				public Object invoke(Invocation invocation) throws Throwable {
					ArtifactResolve req = (ArtifactResolve) invocation.getParameter(0);
					return buildResponse(req.getID(), true, true, reqId);
				}
			});
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(PassiveUserAssertion.class)));
			one(res).sendRedirect("requesturi?query");
		}});
		sh.setSoapClient(client);
		
		sh.handleGet(ctx);
	}
	
	@Test
	public void authenticationHookMustBeInvokedIfConfigured() throws Exception {
		AuthenticationHandlerStub.invoked = false;
		conf.put(Constants.PROP_AUTHENTICATION_HANDLER, AuthenticationHandlerStub.class.getName());
		
		String id = Utils.generateUUID();
		handler.registerRequest(id, idpEntityId);
		ArtifactResponse r = (ArtifactResponse) buildResponse(Utils.generateUUID(), true, false, id).getBody().getUnknownXMLObjects().get(0);
		final String response = Base64.encodeBytes(XMLHelper.nodeToString(SAMLUtil.marshallObject(r.getMessage())).getBytes());
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(response));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(handler.saveRequest(new Request("requesturi", "query", "GET", new HashMap<String, String[]>()))));
			one(session).setAttribute(with(equal(Constants.SESSION_USER_ASSERTION)), with(any(UserAssertion.class)));
			one(res).sendRedirect("requesturi?query");
		}});
		
		AuthenticationHandlerStub.succeed = true;
		sh.handlePost(ctx);
		assertTrue(AuthenticationHandlerStub.invoked);
	}

	@Test
	public void authenticationHookFailureMustAbort() throws Exception {
		AuthenticationHandlerStub.invoked = false;
		conf.put(Constants.PROP_AUTHENTICATION_HANDLER, AuthenticationHandlerStub.class.getName());
		
		String id = Utils.generateUUID();
		handler.registerRequest(id, idpEntityId);
		ArtifactResponse r = (ArtifactResponse) buildResponse(Utils.generateUUID(), true, false, id).getBody().getUnknownXMLObjects().get(0);
		final String response = Base64.encodeBytes(XMLHelper.nodeToString(SAMLUtil.marshallObject(r.getMessage())).getBytes());
		
		context.checking(new Expectations() {{
			allowing(req).getParameter(Constants.SAML_SAMLRESPONSE); will(returnValue(response));
			one(req).getParameter(Constants.SAML_RELAYSTATE); will(returnValue(handler.saveRequest(new Request("requesturi", "query", "GET", new HashMap<String, String[]>()))));
		}});
		
		AuthenticationHandlerStub.succeed = false;
		sh.handlePost(ctx);
		assertTrue(AuthenticationHandlerStub.invoked);
	}
		
	private Envelope buildResponse(String id, boolean sign, boolean passive, String reqId) throws Exception {
		ArtifactResponse res = SAMLUtil.buildXMLObject(ArtifactResponse.class);
		res.setDestination(spMetadata.getEntityID());
		res.setIssuer(SAMLUtil.createIssuer(idpEntityId));
		
		res.setInResponseTo(id);
		res.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
		
		Response samlResponse = SAMLUtil.buildXMLObject(Response.class);
		samlResponse.setInResponseTo(reqId);
		
		Assertion assertion = buildAssertion(spMetadata.getAssertionConsumerServiceLocation(0), spMetadata.getEntityID());
		if (!passive) {
			samlResponse.setStatus(SAMLUtil.createStatus(StatusCode.SUCCESS_URI));
	
			samlResponse.getAssertions().add(assertion);
		} else {
			samlResponse.setStatus(SAMLUtil.createStatus(StatusCode.RESPONDER_URI));
			StatusCode status = SAMLUtil.buildXMLObject(StatusCode.class);
			status.setValue(StatusCode.NO_PASSIVE_URI);
			samlResponse.getStatus().getStatusCode().setStatusCode(status);
		}
		res.setMessage(samlResponse);
		
		if (sign) {
			Signature signature = SAMLUtil.buildXMLObject(Signature.class);
		    signature.setSigningCredential(credential);
	        SecurityHelper.prepareSignatureParams(signature, credential, null, null);
		    samlResponse.setSignature(signature);
		    SAMLUtil.marshallObject(samlResponse);
		    
	        Signer.signObject(signature);
		}
		
		Envelope env = SAMLUtil.buildXMLObject(Envelope.class);
		Body body = SAMLUtil.buildXMLObject(Body.class);
		env.setBody(body);
		body.getUnknownXMLObjects().add(res);
		return env;
	}

	private ByteArrayOutputStream generateArtifact() throws IOException,
			NoSuchAlgorithmException, UnsupportedEncodingException {
		final ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(SAML2ArtifactType0004.TYPE_CODE);
		bos.write(0);
		bos.write(0);
		MessageDigest md = MessageDigest.getInstance(OIOSAMLConstants.SHA_HASH_ALGORHTM);
		bos.write(md.digest("idp1.test.oio.dk".getBytes("UTF-8")));
		bos.write("12345678901234567890".getBytes());
		return bos;
	}
	
	public static class AuthenticationHandlerStub implements AuthenticationHandler {
		static boolean invoked;
		static boolean succeed = true;
		
		public boolean userAuthenticated(UserAssertion assertion, HttpServletRequest request, HttpServletResponse response) {
			invoked = true;
			return succeed;
		}
		
	}
}
