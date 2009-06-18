package dk.sst.oiosaml.wsfed.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;

import org.cyberneko.html.parsers.DOMParser;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.html.HTMLElement;
import org.xml.sax.InputSource;

import com.gargoylesoftware.htmlunit.BrowserVersion;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebWindow;

import dk.itst.oiosaml.sp.service.util.Constants;

public class LoginHandlerTest extends AbstractTests {

	@Test
	public void testRedirect() throws Exception {
		LoginHandler lh = new LoginHandler();
		

		final StringHolder h = new StringHolder();
		doNothing().when(res).sendRedirect(argThat(new BaseMatcher<String>() {
			public boolean matches(Object item) {
				h.value = (String) item;
				return true;
			}

			public void describeTo(Description description) {}
		}));
		when(req.getParameter(Constants.SAML_RELAYSTATE)).thenReturn("relay");
		
		lh.handleGet(rc);
		
		assertNotNull(h.value);
		URI u = URI.create(h.value);
		assertTrue(h.value.startsWith(rc.getIdpMetadata().getFirstMetadata().getSingleSignonServiceLocation(WSFedConstants.WSFED_PROTOCOL)));
		
		Map<String, String> q = parseQuery(u.getQuery());
		assertEquals(rc.getSpMetadata().getAssertionConsumerServiceLocation(0), q.get("wreply"));
		assertEquals("relay", q.get("wctx"));
		assertEquals(WSFedConstants.WSFED_SIGNIN, q.get("wa"));
		assertEquals(rc.getSpMetadata().getEntityID(), q.get("wtrealm"));
		assertNotNull(q.get("wct"));
		
		verify(res).sendRedirect(anyString());
	}
	
	@Test
	public void testPost() throws Exception {
		cfg.setProperty(WSFedConstants.PROP_USE_REDIRECT, false);

		StringWriter sw = new StringWriter();
		when(res.getWriter()).thenReturn(new PrintWriter(sw));
		
		LoginHandler lh = new LoginHandler();
		lh.handleGet(rc);
		
		WebWindow win = mock(WebWindow.class);
		when(win.getScriptObject()).thenThrow(new RuntimeException("test"));
		when(win.getWebClient()).thenReturn(new WebClient(BrowserVersion.FIREFOX_2));
		
		DOMParser parser = new DOMParser();
		parser.parse(new InputSource(new ByteArrayInputStream(sw.toString().getBytes())));
		HTMLElement e = (HTMLElement) parser.getDocument().getDocumentElement();
		
		NodeList forms = e.getElementsByTagName("form");
		assertEquals(1, forms.getLength());
		Element form = (Element)forms.item(0);
		assertEquals("loginform", form.getAttribute("name"));
		assertEquals(rc.getIdpMetadata().getFirstMetadata().getSingleSignonServiceLocation(WSFedConstants.WSFED_PROTOCOL), form.getAttribute("action"));
		
		verify(res, never()).sendRedirect(anyString());
	}
	
	@Test(expected=UnsupportedOperationException.class)
	public void postNotSupported() throws ServletException, IOException {
		new LoginHandler().handlePost(rc);
	}
	
	private class StringHolder {
		String value;
	}
	
	private Map<String, String> parseQuery(String query) {
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
