package dk.itst.saml.poc;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import liberty.sb._2006_08.Framework;
import liberty.sb._2006_08.UserInteraction;

import org.apache.log4j.Logger;

import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;
import dk.itst.saml.poc.provider.RequestInteract;
import dk.itst.saml.poc.provider.RequestToInteractFault;

public class InteractServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(InteractServlet.class);
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String user = UserAssertionHolder.get().getSubject();
		
		ProviderService service = new ProviderService();
		Provider port = service.getProviderPort();
		try {
			RequestInteract requestInteract = new RequestInteract();
			requestInteract.setUser(user);
			
			UserInteraction ui = new UserInteraction();
			ui.setInteract("InteractIfNeeded");
			ui.setRedirect(true);
			
			Framework fw = new Framework();
			fw.setMustUnderstand("1");
			fw.setProfile("egovsimple");
			fw.setVersion("2.0");
			
			String info = port.requestInteract(requestInteract, ui, fw).getReturn();
			log.debug("Info for user " + user + ": " + info);

			req.setAttribute("user", user);
			req.setAttribute("info", info);
			req.getRequestDispatcher("/info.jsp").forward(req, resp);
		} catch (RequestToInteractFault e) {
			String redirectURL = e.getFaultInfo().getRedirectURL();
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
			req.setAttribute("service", service.getServiceName());
			req.setAttribute("url", redirectURL);
			req.setAttribute("message", e.getFaultInfo().getMessage());
			req.getRequestDispatcher("/redirect.jsp").forward(req, resp);
			
//			resp.sendRedirect(redirectURL);
		}
	}
}
