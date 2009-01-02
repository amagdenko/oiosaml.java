package dk.itst.saml.poc;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.trust.SigningPolicy;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustClient;
import dk.itst.oiosaml.trust.TrustConstants;
import dk.itst.oiosaml.trust.TrustException;

public class TokenServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(TokenServlet.class);

	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
	}

	protected void doGet(final HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		try {
			TrustClient tokenClient = new TrustClient();
			tokenClient.setSoapVersion(SOAPConstants.SOAP11_NS);
			tokenClient.setUseReferenceForOnBehalfOf(false);
			tokenClient.setIssuer(SPMetadata.getInstance().getEntityID());
			tokenClient.setIssuer(null);

			SigningPolicy policy = new SigningPolicy(true);
			//		policy.addPolicy(Timestamp.ELEMENT_NAME, true);
			//		policy.addPolicy(To.ELEMENT_NAME, true);
			//		policy.addPolicy(ReplyTo.ELEMENT_NAME, true);
			//		policy.addPolicy(MessageID.ELEMENT_NAME, true);
			tokenClient.setSigningPolicy(policy);

			UserAttribute bootstrap = UserAssertionHolder.get().getAttribute(TrustConstants.DISCOVERY_EPR_ATTRIBUTE);
			log.debug("Bootstrap data: " + bootstrap);
			String xml = bootstrap.getValue();
			log.debug("XML: " + xml);
			req.setAttribute("epr", xml);


			try {
				String endpoint = SAMLConfiguration.getSystemConfiguration().getString("poc.provider");
				tokenClient.setAppliesTo(endpoint);
				Element stsToken = tokenClient.getToken(TrustConstants.DIALECT_OCES_PROFILE);

				String stsXml = XMLHelper.nodeToString(stsToken);
				req.getSession().setAttribute("token", stsXml);

				req.setAttribute("message", stsXml);
				log.debug("SAML token: " + stsXml);

				req.getRequestDispatcher("/sp/ticket.jsp").forward(req, resp);
			} catch (TrustException e) {
				log.error("Unable to complete request", e);
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
