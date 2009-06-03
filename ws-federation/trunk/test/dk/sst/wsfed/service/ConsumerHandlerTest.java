package dk.sst.wsfed.service;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.MapConfiguration;
import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.sst.oiosaml.wsfed.service.ConsumerHandler;
import dk.sst.oiosaml.wsfed.service.FederationUserAssertion;

public class ConsumerHandlerTest {
	
	private RequestContext rc;
	private Configuration cfg;
	private SessionHandler sh;
	private HttpServletResponse res;
	private HttpSession session;
	private HttpServletRequest req;
	private ConsumerHandler handler;

	@BeforeClass
	public static void config() {
		TrustBootstrap.bootstrap();
	}
	
	@Before
	public void setUp() throws Exception {
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
		rc = new RequestContext(req, res, null, new SPMetadata(desc, "http://schemas.xmlsoap.org/ws/2006/12/federation"), credential, cfg, sh, null);
		handler = new ConsumerHandler(cfg);
	}

	@Test
	
	public void testSignin() throws Exception {
		when(req.getParameter("wa")).thenReturn("wsignin1.0");
		when(req.getParameter("wresult")).thenReturn(IOUtils.toString(getClass().getResourceAsStream("/rstr.xml")));
		
		handler.handleGet(rc);
		
		verify(sh).setAssertion(anyString(), any(OIOAssertion.class));
		verify(session).setAttribute(anyString(), any(FederationUserAssertion.class));
		verify(res).sendRedirect("/home");
	}
	
	@Test
	public void testSignoutWhenNotLoggedIn() throws Exception {
		when(req.getParameter("wa")).thenReturn("wsignout1.0");
		handler.handleGet(rc);
		
		verify(res).sendError(HttpServletResponse.SC_UNAUTHORIZED);
		verify(res).setContentType("image/gif");
	}
	
	@Test
	public void testSignoutDefault() throws Exception {
		when(sh.isLoggedIn(anyString())).thenReturn(true);
		Assertion a = SAMLUtil.buildXMLObject(Assertion.class);
		a.setSubject(SAMLUtil.createSubject("test", "test", new DateTime()));
		when(sh.getAssertion(anyString())).thenReturn(new OIOAssertion(a));
		when(req.getParameter("wa")).thenReturn("wsignout1.0");
		
		handler.handleGet(rc);
		
		verify(res).setContentType("image/gif");
		verify(sh).logOut(session);
		verify(res, never()).sendError(anyInt());
	}
	
	@Test
	public void testLogoutRedirect() throws Exception {
		when(sh.isLoggedIn(anyString())).thenReturn(true);
		Assertion a = SAMLUtil.buildXMLObject(Assertion.class);
		a.setSubject(SAMLUtil.createSubject("test", "test", new DateTime()));
		when(sh.getAssertion(anyString())).thenReturn(new OIOAssertion(a));
		when(req.getParameter("wa")).thenReturn("wsignout1.0");
		when(req.getParameter("wreply")).thenReturn("/result");
		
		handler.handleGet(rc);
		
		verify(sh).logOut(session);
		verify(res).sendRedirect("/result");
	}
	
	public static class Validator implements AssertionValidator {
		public void validate(OIOAssertion assertion, String spEntityId,
				String spAssertionConsumerURL) throws ValidationException {
			
		}
	}
}
