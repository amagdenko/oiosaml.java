package dk.sst.oiosaml.wsfed.service;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.AssertionValidator;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.sst.oiosaml.wsfed.FederationUserAssertion;

public class ConsumerHandlerTest extends AbstractTests {
	
	private ConsumerHandler handler;

	@Before
	public void setup() {
		handler = new ConsumerHandler(cfg);
	}
	
	@Test
	public void testSignin() throws Exception {
		when(req.getParameter("wa")).thenReturn("wsignin1.0");
		RequestSecurityTokenResponse resp = (RequestSecurityTokenResponse) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/rstr.xml"));
		resp.getLifetime().getExpires().setDateTime(new DateTime().plusMinutes(5));
		SAMLUtil.getFirstElement(resp.getAppliesTo(), EndpointReference.class).getAddress().setValue(rc.getSpMetadata().getAssertionConsumerServiceLocation(0));
		when(req.getParameter("wresult")).thenReturn(XMLHelper.nodeToString(SAMLUtil.marshallObject(resp)));
		
		handler.handleGet(rc);
		
		verify(sh).setAssertion(anyString(), any(OIOAssertion.class));
		verify(session).setAttribute(anyString(), any(FederationUserAssertion.class));
		verify(res).sendRedirect("/home");
	}
	
	@Test(expected=ValidationException.class)
	public void testSigninValidationFailsWhenLifetimeExpired() throws Exception {
		when(req.getParameter("wa")).thenReturn("wsignin1.0");
		RequestSecurityTokenResponse resp = (RequestSecurityTokenResponse) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/rstr.xml"));
		resp.getLifetime().getExpires().setDateTime(new DateTime().minusMinutes(1));
		when(req.getParameter("wresult")).thenReturn(XMLHelper.nodeToString(SAMLUtil.marshallObject(resp)));
		
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
