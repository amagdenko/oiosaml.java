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
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustClient;
import dk.itst.saml.poc.provider.Echo;
import dk.itst.saml.poc.provider.EchoResponse;
import dk.itst.saml.poc.provider.Provider;
import dk.itst.saml.poc.provider.ProviderService;

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
		TrustClient tokenClient = new TrustClient();
		
		String endpoint = (String) bp.getRequestContext().get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY);
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
		request.setInput("");
		generateRequest(req, request);
		
		EchoResponse response = (EchoResponse) Utils.request(request, tokenClient, bp, "http://provider.poc.saml.itst.dk/Provider" + (simple ? "Simple" : "") + "/echoRequest");
		req.setAttribute("spRequest", tokenClient.getLastRequestXML());
		req.setAttribute("spResponse", response.getOutput());
		
		req.getRequestDispatcher("/sp/token.jsp").forward(req, resp);

	}

	private void generateRequest(final HttpServletRequest req, Echo request) {
		if (req.getParameter("length") == null ) return;
		
		int length = Integer.parseInt(req.getParameter("length"));
		
		byte[] r = new byte[length];
		for (int i = 0; i < r.length; i++) {
			r[i] = (byte) (48 + (i % 70));
		}
		
		request.setInput(new String(r));
	}
}