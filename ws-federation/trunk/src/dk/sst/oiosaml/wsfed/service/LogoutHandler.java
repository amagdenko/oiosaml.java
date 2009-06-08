package dk.sst.oiosaml.wsfed.service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import dk.itst.oiosaml.logging.Audit;
import dk.itst.oiosaml.logging.Operation;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.SAMLHandler;
import dk.itst.oiosaml.sp.service.util.Constants;

public class LogoutHandler implements SAMLHandler {
	private static final Logger log = Logger.getLogger(LogoutHandler.class);

	public void handleGet(RequestContext context) throws ServletException, IOException {
		HttpSession session = context.getSession();

		// Check that user is logged in...
		if (!context.getSessionHandler().isLoggedIn(session.getId())) {
			String homeUrl = context.getConfiguration().getString(Constants.PROP_HOME, context.getRequest().getContextPath());
			context.getResponse().sendRedirect(homeUrl);
			return;
		}
		
		OIOAssertion assertion = context.getSessionHandler().getAssertion(session.getId());
		String entityID = assertion.getAssertion().getIssuer().getValue();
		Metadata metadata = context.getIdpMetadata().getMetadata(entityID);
		StringBuilder url = new StringBuilder(metadata.getSingleLogoutServiceLocation());
		if (url.indexOf("?") == -1) {
			url.append('?');
		}
		url.append("?wa=wsignout1.0");

		Audit.log(Operation.LOGOUTREQUEST, true, null, url.toString());

		log.debug("Redirecting " + assertion.getSubjectNameIDValue() + " to " + url);
		Audit.log(Operation.LOGOUT, assertion.getSubjectNameIDValue());
		context.getResponse().sendRedirect(url.toString());
	}

	public void handlePost(RequestContext arg0) throws ServletException, IOException {
		throw new UnsupportedOperationException();
	}

}
