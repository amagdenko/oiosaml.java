package dk.itst.saml.poc;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.ws.BindingProvider;

import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.trust.ResultHandler;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustClient;
import dk.itst.saml.poc.provider.Echo;
import dk.itst.saml.poc.provider.EchoResponse;
import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;
import dk.itst.saml.poc.provider.Structure;

public class RequestServlet extends HttpServlet {

	private Provider port;
	private BindingProvider bp;

	@Override
	public void init(ServletConfig config) throws ServletException {
		TrustBootstrap.bootstrap();
		port = new ProviderService().getProviderPort();
		bp = (BindingProvider) port;
	}

	protected void doGet(final HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getSession().getAttribute("token") == null) {
			resp.sendRedirect("token");
			return;
		}
		final TrustClient tokenClient = new TrustClient();
		
		String endpoint = SAMLConfiguration.getSystemConfiguration().getString("poc.provider");
		tokenClient.setAppliesTo(endpoint);
		tokenClient.setIssuer(SPMetadata.getInstance().getEntityID());

		boolean simple = req.getParameter("simple") != null;
		tokenClient.signRequests(!simple);
		if (simple) {
			bp.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endpoint.replaceAll("ProviderService", "ProviderSimpleService"));
		} else {
			bp.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endpoint.replaceAll("ProviderSimpleService", "ProviderService"));
			tokenClient.setToken((Assertion) SAMLUtil.unmarshallElementFromString((String) req.getSession().getAttribute("token")));
		}

		Echo request = new Echo();
		generateRequest(req, request);
		
		tokenClient.sendRequest(request, Utils.getJAXBContext(), endpoint, "http://provider.poc.saml.itst.dk/Provider" + (simple ? "Simple" : "") + "/echoRequest", null, new ResultHandler<EchoResponse>() {
			public void handleResult(EchoResponse result) throws Exception {
				req.setAttribute("spRequest", tokenClient.getLastRequestXML());
				req.setAttribute("spResponse", result.getOutput());
			}
		});
		req.getRequestDispatcher("/sp/token.jsp").forward(req, resp);

	}

	private void generateRequest(final HttpServletRequest req, Echo request) {
		if (req.getParameter("length") == null ) return;
		
		int length = Integer.parseInt(req.getParameter("length"));
		
		Structure s = new Structure();
		generate(s, length, 0);
		
		request.setInput(s);
	}
	
	private void generate(Structure root, int length, int depth) {
		if (length < depth) return;
		
		for (int i = 0; i < length; i++) {
			Structure structure = new Structure();
			structure.setValue(i + ":" + depth);
			root.getStructure().add(structure);
			
			generate(structure, length, depth + 1);
		}
	}
}
