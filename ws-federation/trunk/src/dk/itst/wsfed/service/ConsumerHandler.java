package dk.itst.wsfed.service;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.AuthenticationHandler;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.OIOEncryptedAssertion;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.SAMLHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HTTPUtils;
import dk.itst.oiosaml.sp.service.util.Utils;

public class ConsumerHandler implements SAMLHandler {
	private static final Logger log = Logger.getLogger(ConsumerHandler.class);
	private AssertionValidator validator;

	public ConsumerHandler(Configuration config) {
		this.validator = (AssertionValidator) Utils.newInstance(config, Constants.PROP_VALIDATOR);
	}

	public void handleGet(RequestContext context) throws ServletException, IOException {
		String response = context.getRequest().getParameter("wresult");
		String relayState = context.getRequest().getParameter("wctx");
		String op = context.getRequest().getParameter("wa");
		
		log.debug("Received result " + response);
		
		
		if ("wsignin1.0".equals(op)) {
			XMLObject r = SAMLUtil.unmarshallElementFromString(response);
			if (r instanceof Envelope && (((Envelope)r).getBody()).getUnknownXMLObjects().get(0) instanceof Fault) {
				Fault f =  (Fault) (((Envelope)r).getBody()).getUnknownXMLObjects().get(0);
				log.error("Request failed: " + XMLHelper.nodeToString(SAMLUtil.marshallObject(f)));
				throw new RuntimeException("Request failed: " + f.getCode().getValue());
			}
			log.debug(r);
			handleSignin(relayState, r, context);
		} else if ("wsignout1.0".equals(op)) {
			String replyTo = context.getRequest().getParameter("wreply");
			handleSignout(context, replyTo);
		} else {
			log.error("Received unknown wa attribute " + op);
			throw new RuntimeException("Unknown wa " + op);
		}
		
		
	}

	private void handleSignout(RequestContext context, String replyTo) throws IOException {
		if (!context.getSessionHandler().isLoggedIn(context.getSession().getId())) {
			log.error("Logout received, but user not authenticated");
			
			context.getResponse().sendError(HttpServletResponse.SC_UNAUTHORIZED);
			ServletOutputStream os = context.getResponse().getOutputStream();
			InputStream image = getClass().getResourceAsStream("logout_error.gif");
			context.getResponse().setContentType("image/gif");
			
			IOUtils.copy(image, os);
			image.close();
			return;
		}
		
		OIOAssertion assertion = context.getSessionHandler().getAssertion(context.getSession().getId());
		Audit.log(Operation.LOGOUT, assertion.getSubjectNameIDValue());
		context.getSessionHandler().logOut(context.getSession());

		if (replyTo == null) {
			ServletOutputStream os = context.getResponse().getOutputStream();
			InputStream image = getClass().getResourceAsStream("logout_ok.gif");
			context.getResponse().setContentType("image/gif");
			
			IOUtils.copy(image, os);
			image.close();
			return;
		} else {
			log.debug("Redirecting to " + replyTo);
			context.getResponse().sendRedirect(replyTo);
		}
	}

	private void handleSignin(String relayState, XMLObject r, RequestContext context) throws IllegalArgumentException, IOException, ServletException {
		OIOAssertion assertion = null;
		if (r instanceof RequestSecurityTokenResponse) {
			RequestSecurityTokenResponse res = (RequestSecurityTokenResponse) r;
			
			XMLObject rt = res.getRequestedSecurityToken().getUnknownXMLObjects().get(0);
			if (rt instanceof Assertion) {
				assertion = new OIOAssertion((Assertion) rt);
			} else if (rt instanceof EncryptedAssertion) {
				OIOEncryptedAssertion ea = new OIOEncryptedAssertion((EncryptedAssertion) rt);
				assertion = ea.decryptAssertion(context.getCredential());
			}
		}
		
		if (assertion == null) {
			throw new RuntimeException("No SAML2 assertion received in response " + r);
		}
		
		assertion.validateAssertion(validator, context.getSpMetadata().getEntityID(), context.getSpMetadata().getAssertionConsumerServiceLocation(0));

		UserAssertion userAssertion = new FederationUserAssertionImpl(assertion);
		if (!invokeAuthenticationHandler(context, userAssertion)) {
			log.error("Authentication handler stopped authentication");
			return;
		}
		
		// Store the assertion in the session store
		HttpSession session = context.getSession();
		context.getSessionHandler().setAssertion(session.getId(), assertion);
		session.setAttribute(Constants.SESSION_USER_ASSERTION, userAssertion);
		
		HTTPUtils.sendResponse(context.getSessionHandler().getRequest(relayState), context);
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		handleGet(context);
	}

	private boolean invokeAuthenticationHandler(RequestContext ctx, UserAssertion userAssertion) {
		String handlerClass = ctx.getConfiguration().getString(Constants.PROP_AUTHENTICATION_HANDLER, null);
		if (handlerClass != null) {
			log.debug("Authentication handler: " + handlerClass);
			
			AuthenticationHandler handler = (AuthenticationHandler) Utils.newInstance(ctx.getConfiguration(), Constants.PROP_AUTHENTICATION_HANDLER);
			return handler.userAuthenticated(userAssertion, ctx.getRequest(), ctx.getResponse());
		} else {
			log.debug("No authentication handler configured");
			return true;
		}
	}
}
