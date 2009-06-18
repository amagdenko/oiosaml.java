package dk.sst.oiosaml.wsfed.service;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.MapConfiguration;
import org.junit.Before;
import org.junit.BeforeClass;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.sst.oiosaml.wsfed.service.ConsumerHandlerTest.Validator;

public abstract class AbstractTests {

	@BeforeClass
	public static void config() {
		TrustBootstrap.bootstrap();
	}

	protected HttpServletRequest req;
	protected HttpServletResponse res;
	protected HttpSession session;
	protected SessionHandler sh;
	protected MapConfiguration cfg;
	protected RequestContext rc;
	
	@Before
	public final void onSetUp() throws Exception {
		req = mock(HttpServletRequest.class);
		res = mock(HttpServletResponse.class);
		when(res.getOutputStream()).thenReturn(new ServletOutputStream() {
			public void write(int b) throws IOException {}
		});
		
		session = mock(HttpSession.class);
		when(req.getSession()).thenReturn(session);
		when(session.getId()).thenReturn(UUID.randomUUID().toString());
		
		EntityDescriptor desc = (EntityDescriptor) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("SPMetadata.xml"));
		
		sh = mock(SessionHandler.class);
		
		CredentialRepository rep = new CredentialRepository();
		BasicX509Credential credential = rep.getCredential("test/test.pkcs12", "Test1234");
		
		cfg = new MapConfiguration(new HashMap<String, Object>() {{
			put("oiosaml-sp.assertion.validator", Validator.class.getName());
			put(Constants.PROP_HOME, "/home");
		}});
		IdpMetadata idp = new IdpMetadata("http://schemas.xmlsoap.org/ws/2006/12/federation", (EntityDescriptor)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("IdPMetadata.xml")));
		rc = new RequestContext(req, res, idp, new SPMetadata(desc, "http://schemas.xmlsoap.org/ws/2006/12/federation"), credential, cfg, sh, null);
	}

	protected Map<String, String> parseQuery(String query) {
		Map<String, String> res = new HashMap<String, String>();
		
		for (String e : query.split("&")) {
			String[] p = e.split("=");
			try {
				res.put(p[0], URLDecoder.decode(p[1], "UTF-8"));
			} catch (UnsupportedEncodingException e1) {}
		}
		
		return res;
	}

}
