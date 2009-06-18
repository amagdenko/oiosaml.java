package dk.sst.oiosaml.wsfed.service;

import java.net.URL;
import java.util.Map;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.*;

public class LogoutHandlerTest extends AbstractTests {

	@Test
	public void redirectIfNotAuthenticated() throws Exception {
		when(sh.isLoggedIn(anyString())).thenReturn(false);
		
		cfg.setProperty(Constants.PROP_HOME, "/home");
		
		LogoutHandler lh = new LogoutHandler();
		lh.handleGet(rc);
		
		verify(res).sendRedirect("/home");
		verifyNoMoreInteractions(res);
	}
	
	@Test
	public void testRedirectToIdP() throws Exception {
		when(sh.isLoggedIn(anyString())).thenReturn(true);
		
		Assertion assertion = SAMLUtil.buildXMLObject(Assertion.class);
		assertion.setIssuer(SAMLUtil.createIssuer(rc.getIdpMetadata().getFirstMetadata().getEntityID()));
		
		when(sh.getAssertion(anyString())).thenReturn(new OIOAssertion(assertion));
		
		final StringHolder h = new StringHolder();
		doNothing().when(res).sendRedirect(argThat(new BaseMatcher<String>() {
			public boolean matches(Object item) {
				h.value = (String) item;
				return true;
			}
			public void describeTo(Description description) {}
		}));

		LogoutHandler lh = new LogoutHandler();
		lh.handleGet(rc);

		verify(res).sendRedirect(anyString());
		assertNotNull(h.value);
		URL url = new URL(h.value);
		assertTrue(h.value.startsWith(rc.getIdpMetadata().getFirstMetadata().getSingleLogoutServiceLocation()));
		
		Map<String, String> q = parseQuery(url.getQuery());
		assertEquals(WSFedConstants.WSFED_SIGNOUT, q.get("wa"));
	}
	
	private class StringHolder {
		String value;
	}

}
