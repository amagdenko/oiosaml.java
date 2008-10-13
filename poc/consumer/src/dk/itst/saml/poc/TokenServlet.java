package dk.itst.saml.poc;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.ws.BindingProvider;

import liberty.sb._2006_08.Framework;

import org.apache.log4j.Logger;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.trust.TokenClient;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustException;
import dk.itst.saml.poc.provider.Echo;
import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;

public class TokenServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(TokenServlet.class);

	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
	}
	
	protected void doGet(final HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		TokenClient tokenClient = new TokenClient();
		
		UserAttribute bootstrap = UserAssertionHolder.get().getAttribute("DiscoveryEPR");
		log.debug("Bootstrap data: " + bootstrap);
		String xml = bootstrap.getValue();
		log.debug("XML: " + xml);
		req.setAttribute("epr", xml);
		
		try {
			try {
				Provider port = new ProviderService().getProviderPort();
				BindingProvider bp = (BindingProvider) port;
				
				tokenClient.setAppliesTo((String) bp.getRequestContext().get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY));
				tokenClient.setIssuer(SPMetadata.getInstance().getEntityID());
				Element stsToken = tokenClient.request();
	
				req.setAttribute("message", XMLHelper.nodeToString(stsToken));
				log.debug("SAML Token: " + req.getAttribute("token"));
				
				AssertionHolder.set(stsToken);
				
				
				Framework fw = new Framework();
				fw.setVersion("2.0");
				fw.setProfile("egovsimple");
				req.setAttribute("spResponse", port.echo(new Echo(), fw).getReturn());
				

				
				req.getRequestDispatcher("/sp/ticket.jsp").forward(req, resp);

			} catch (TrustException e) {
				req.setAttribute("detail", e.getMessage());
				req.getRequestDispatcher("/sp/ticketfault.jsp").forward(req, resp);
			}
		} catch (Exception e) {
			e.printStackTrace();
			resp.setContentType("text/plain");
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			e.printStackTrace(resp.getWriter());
		}
	}
}
