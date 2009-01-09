package dk.itst.saml.poc;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import liberty.sb._2006_08.RedirectRequest;

import org.apache.log4j.Logger;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.liberty.LibertyConstants;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.trust.FaultHandler;
import dk.itst.oiosaml.trust.ResultHandler;
import dk.itst.oiosaml.trust.ServiceClient;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustClient;
import dk.itst.saml.poc.provider.RequestInteract;
import dk.itst.saml.poc.provider.RequestInteractResponse;

public class InteractServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(InteractServlet.class);
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
	}
	
	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		String endpoint = SAMLConfiguration.getSystemConfiguration().getString("poc.provider");
		
		final String user = UserAssertionHolder.get().getSubject();

		TrustClient tokenClient = new TrustClient();
		tokenClient.setAppliesTo(endpoint);
		tokenClient.setIssuer(SPMetadata.getInstance().getEntityID());
		tokenClient.getToken();
		ServiceClient serviceClient = tokenClient.getServiceClient();

		serviceClient.setUserInteraction(dk.itst.oiosaml.trust.UserInteraction.IF_NEEDED, true);
		try {
			RequestInteract requestInteract = new RequestInteract();
			requestInteract.setUser(user);

			serviceClient.addFaultHander(LibertyConstants.SB_NS, "RedirectRequest", new FaultHandler() {
				public void handleFault(QName code, String msg, XMLObject fault) throws Exception {
					RedirectRequest rr = (RedirectRequest) Utils.unmarshall(fault);
					String redirectURL = rr.getRedirectURL();
					log.debug("Received RTI to " + redirectURL);
					
					if (redirectURL.indexOf("?") > -1) {
						redirectURL += "&";
					} else {
						redirectURL += "?";
					}
					req.getQueryString();
					redirectURL+= "ReturnToURL=";
					
					String requestURL = req.getRequestURL().toString();
					if (req.getQueryString() != null) {
						requestURL += "?" + req.getQueryString();
					}
					redirectURL += URLEncoder.encode(requestURL, "UTF-8");
					
					log.debug("Redirecting to " + redirectURL);
					
					req.setAttribute("request", "requestInteract");
					req.setAttribute("service", "ProviderService");
					req.setAttribute("url", redirectURL);
					req.setAttribute("message", rr.getMessage());
					req.getRequestDispatcher("/redirect.jsp").forward(req, resp);
					
//					resp.sendRedirect(redirectURL);
				}
			});
			serviceClient.sendRequest(requestInteract, Utils.getJAXBContext(), endpoint, "http://provider.poc.saml.itst.dk/Provider/requestInteractRequest", null, new ResultHandler<RequestInteractResponse>() {
				public void handleResult(RequestInteractResponse res) throws ServletException, IOException {
					String info = res.getReturn();
					log.debug("Info for user " + user + ": " + info);

					req.setAttribute("user", user);
					req.setAttribute("info", info);
					req.getRequestDispatcher("/info.jsp").forward(req, resp);
				}
			});
			
		} catch (Exception e) {
			log.error("Unable to process", e);
			throw new ServletException(e);
		} finally {}
	}
}
