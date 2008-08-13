package dk.itst.saml.poc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500PrivateCredential;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.log4j.Logger;
import org.openliberty.wsc.OpenLibertyBootstrap;
import org.openliberty.xmltooling.disco.SecurityContext;
import org.openliberty.xmltooling.security.Token;
import org.openliberty.xmltooling.wsa.EndpointReference;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import com.pingidentity.sts.clientapi.STSClient;
import com.pingidentity.sts.clientapi.STSClientException;
import com.pingidentity.sts.clientapi.authentication.HTTPAuthentication;
import com.pingidentity.sts.clientapi.model.RequestSecurityTokenData;
import com.pingidentity.sts.clientapi.model.STSResponse;
import com.pingidentity.sts.clientapi.protocol.KeyIdentifierTokenReference;
import com.pingidentity.sts.clientapi.protocol.KeyIdentifierTokenReference.IdProvider;
import com.sun.xml.ws.developer.JAXWSProperties;

import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.BRSUtil;
import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;

public class TokenServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(TokenServlet.class);

	@Override
	public void init(ServletConfig config) throws ServletException {
		try {
			OpenLibertyBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new ServletException(e);
		}
	}
	
	protected void doGet(final HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		BasicX509Credential credential = Utils.getCredential("/home/recht/download/TestMOCES1.pfx", "Test1234");
		HTTPAuthentication auth = null;// new HTTPAuthentication("test", "test");
		
		UserAttribute bootstrap = UserAssertionHolder.get().getAttribute("DiscoveryEPR");
		log.debug("Bootstrap data: " + bootstrap);
		String xml = bootstrap.getValue();
		log.debug("XML: " + xml);
		req.setAttribute("epr", xml);
		
		EndpointReference epr = (EndpointReference) BRSUtil.unmarshallElementFromString(xml);
		epr.getMetadata().getServiceTypes(); //TODO: check for correct service type
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getSecurityContexts());

		OIOAssertion ass = new OIOAssertion(token.getAssertion());
		ass.sign(credential);
		req.setAttribute("request", ass.toXML());		

		STSClient client = new STSClient(epr.getAddress().getValue());
		client.registerSecurityTokenReference(new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion"), KeyIdentifierTokenReference.SAML20_TOKEN_TYPE, 
				new KeyIdentifierTokenReference(KeyIdentifierTokenReference.SAML20_TOKEN_TYPE, KeyIdentifierTokenReference.SAML20_VALUE_TYPE, new IdProvider() {
					public String obtainId(Element e) throws STSClientException {
						log.debug("Resolving id for " + e);
						return e.getAttribute("ID");
					}
				}));
		
		
		RequestSecurityTokenData data = client.createIssueData();
		data.setAppliesTo("http://jre-mac.trifork.com");
		data.setTokenType(KeyIdentifierTokenReference.SAML20_TOKEN_TYPE);
		
		try {
			STSResponse response = client.makeRequest(data, ass.getAssertion().getDOM(), auth, KeyIdentifierTokenReference.SAML20_TOKEN_TYPE, new X500PrivateCredential(credential.getEntityCertificate(), credential.getPrivateKey()));
			log.debug("Fault: " + response.isFault());
			log.debug("Message: " + response.getStsMessage());
			log.debug("Rstr: " + response.getRstr());
			
			if (response.isFault()) {
				req.setAttribute("detail", response.getSoapFault().getDetail());
				req.setAttribute("actor", response.getSoapFault().getFaultActor());
				req.setAttribute("code", response.getSoapFault().getFaultCode());
				req.setAttribute("message", response.getSoapFault().getFaultString());
				
				req.getRequestDispatcher("/sp/ticketfault.jsp").forward(req, resp);
			} else {
				req.setAttribute("message", XMLHelper.nodeToString(response.getStsMessage().toDocument().getDocumentElement()));
				req.setAttribute("status", response.getRstr().getStatusCode());
				req.setAttribute("type", response.getRstr().getTokenType());
				req.setAttribute("rstr", XMLHelper.nodeToString(response.getRstr().getRstrElement()));
				req.setAttribute("token", XMLHelper.nodeToString(response.getRstr().getToken()));
				log.debug("SAML Token: " + req.getAttribute("token"));
				
				AssertionHolder.set(response.getRstr().getToken());
				
				Provider port = new ProviderService().getProviderPort();
				req.setAttribute("spResponse", port.echo());
				

				
				req.getRequestDispatcher("/sp/ticket.jsp").forward(req, resp);
			}
		} catch (Exception e) {
			e.printStackTrace();
			resp.setContentType("text/plain");
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			e.printStackTrace(resp.getWriter());
//			throw new ServletException("Unable to retrieve STS token", e);
		}
	}
	
	private Token getToken(String usage, Collection<SecurityContext> contexts) {
		for (SecurityContext ctx : contexts) {
			for (Token t : ctx.getTokens()) {
				if (usage.equals(t.getUsage())) {
					return t;
				}
			}
			
		}
		throw new IllegalArgumentException("No token with usage type " + usage);
	}
}
