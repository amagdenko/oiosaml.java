package dk.itst.oiosaml.authz;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.MapConfiguration;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JMock;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSAnyUnmarshaller;

import dk.itst.oiosaml.configuration.BRSConfiguration;
import dk.itst.oiosaml.sp.OIOPrincipal;
import dk.itst.oiosaml.sp.UserAssertionImpl;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.util.AttributeUtil;
import dk.itst.oiosaml.sp.util.BRSUtil;


@RunWith(JMock.class)
public class AuthzFilterTest {
	private Mockery context = new Mockery();
	private HttpServletRequest req;
	private HttpServletResponse res;
	private AuthzFilter filter;
	private Map<String, String> props = new HashMap<String, String>();
	private String configFile;
	private FilterChain chain;

	@Before
	public void setUp() throws IOException, ServletException {
		req = context.mock(HttpServletRequest.class);
		res = context.mock(HttpServletResponse.class);
		chain = context.mock(FilterChain.class);
		context.checking(new Expectations() {{
			allowing(req).getServletPath(); will(returnValue("/servlet"));
		}});
		
		filter = new AuthzFilter();

		props.put(BRSUtil.OIOSAML_HOME, System.getProperty("java.io.tmpdir"));
		BRSConfiguration.setSystemConfiguration(new MapConfiguration(props));
		
		configFile = generateConfigFile();
		
		props.put(Constants.PROP_PROTECTION_CONFIG_FILE, configFile);
		filter.init(null);
	}
	
	@Test(expected=ServletException.class)
	public void failWhenNoConfigFile() throws ServletException {
		filter = new AuthzFilter();
		props.clear();
		filter.init(null);
	}
	
	@Test(expected=ServletException.class)
	public void failOnNoAssertion() throws Exception {
		context.checking(new Expectations() {{
			one(req).getUserPrincipal(); will(returnValue(null));
		}});
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void denyOnNoAuthorisationsAndDefaultDeny() throws Exception {
		final OIOAssertion assertion = getAssertion("assertion.xml", "1029275212");
		
		context.checking(new Expectations() {{
			one(req).getUserPrincipal(); will(returnValue(new OIOPrincipal(new UserAssertionImpl(assertion))));
			one(req).getRequestURI(); will(returnValue("/test"));
			one(req).getMethod(); will(returnValue("get"));
			one(req).getContextPath(); will(returnValue(""));
			one(res).sendError(with(equal(HttpServletResponse.SC_FORBIDDEN)), with(any(String.class)));
		}});
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void failOnNoEmployeeIdentifier() throws Exception {
		final OIOAssertion assertion = getAssertion("assertion.xml", null);
		context.checking(new Expectations() {{
			one(req).getUserPrincipal(); will(returnValue(new OIOPrincipal(new UserAssertionImpl(assertion))));
			one(res).sendError(with(equal(HttpServletResponse.SC_FORBIDDEN)), with(any(String.class)));
		}});
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void failOnMissingPrivilege() throws Exception {
		final OIOAssertion assertion = getAssertion("assertion.xml", "1029275212");

		Attribute attr = AttributeUtil.createAttribute(Constants.AUTHORISATIONS_ATTRIBUTE, "", "uri");
		XSAnyBuilder builder = new XSAnyBuilder();
		XSAny ep = builder.buildObject(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);

		XSAnyUnmarshaller unmarshaller = new XSAnyUnmarshaller();
		XMLObject val = unmarshaller.unmarshall(BRSUtil.loadElementFromString(IOUtils.toString(getClass().getResourceAsStream("authorisations.xml"))));
		ep.getUnknownXMLObjects().add(val);
		attr.getAttributeValues().add(ep);
		
		assertion.getAssertion().getAttributeStatements().get(0).getAttributes().add(attr);
		
		context.checking(new Expectations() {{
			one(req).getUserPrincipal(); will(returnValue(new OIOPrincipal(new UserAssertionImpl(assertion))));
			one(req).getRequestURI(); will(returnValue("/context/admin"));
			one(req).getContextPath(); will(returnValue("/context"));
			one(req).getMethod(); will(returnValue("post"));
			one(res).sendError(with(equal(HttpServletResponse.SC_FORBIDDEN)), with(any(String.class)));
		}});
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void testGrantAccess() throws Exception {
		final OIOAssertion assertion = getAssertion("assertion.xml", "1029275212");

		Attribute attr = AttributeUtil.createAttribute(Constants.AUTHORISATIONS_ATTRIBUTE, "", "uri");
		XSAnyBuilder builder = new XSAnyBuilder();
		XSAny ep = builder.buildObject(SAMLConstants.SAML20_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20_PREFIX);

		XSAnyUnmarshaller unmarshaller = new XSAnyUnmarshaller();
		XMLObject val = unmarshaller.unmarshall(BRSUtil.loadElementFromString(IOUtils.toString(getClass().getResourceAsStream("authorisations.xml"))));
		ep.getUnknownXMLObjects().add(val);
		attr.getAttributeValues().add(ep);
		
		assertion.getAssertion().getAttributeStatements().get(0).getAttributes().add(attr);
		
		context.checking(new Expectations() {{
			one(req).getUserPrincipal(); will(returnValue(new OIOPrincipal(new UserAssertionImpl(assertion))));
			one(req).getRequestURI(); will(returnValue("/context/test"));
			one(req).getContextPath(); will(returnValue("/context"));
			one(req).getMethod(); will(returnValue("post"));
			one(chain).doFilter(req, res);
		}});
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void alwaysGrantAccessOnSAMLServletRequest() throws Exception {
		props.put(dk.itst.oiosaml.sp.service.util.Constants.PROP_SAML_SERVLET, "/servlet");
		context.checking(new Expectations() {{
			one(chain).doFilter(req, res);
		}});
		filter.doFilter(req, res, chain);
	}
	
	@Test
	public void testErrorServetOnAccessDenied() throws Exception{
		// if an error servlet has been defined in config, use it instead of sending standard 403 error.
		
		props.put(Constants.PROP_PROTECTION_ERROR_SERVLET, "/error");
		final OIOAssertion assertion = getAssertion("assertion.xml", "1029275212");
		
		context.checking(new Expectations() {{
			one(req).getUserPrincipal(); will(returnValue(new OIOPrincipal(new UserAssertionImpl(assertion))));
			one(req).getRequestURI(); will(returnValue("/test"));
			one(req).getMethod(); will(returnValue("get"));
			one(req).getContextPath(); will(returnValue(""));
			one(req).getRequestDispatcher("/error");
		}});
		filter.doFilter(req, res, chain);
		
	}
	
	private String generateConfigFile() throws IOException {
		String xml = IOUtils.toString(getClass().getResourceAsStream("protections.xml"));
		
		File file = File.createTempFile("oiosaml-authz", ".xml");
		FileUtils.writeStringToFile(file, xml);
		
		return file.getName();
	}
	
	private OIOAssertion getAssertion(String name, String pCode) throws IOException {
		Assertion assertion = (Assertion) BRSUtil.unmarshallElementFromString(IOUtils.toString(getClass().getResourceAsStream(name)));
		if (pCode != null) {
			Attribute attr = AttributeUtil.createAttribute(Constants.PRODUCTION_CODE_ATTRIBUTE, null, "");
			attr.getAttributeValues().add(AttributeUtil.createAttributeValue(pCode));
			assertion.getAttributeStatements().get(0).getAttributes().add(attr);
		}
		
		return new OIOAssertion(assertion);
	}
	
	@After
	public void tearDown() {
		new File(new File(System.getProperty("java.io.tmpdir")), configFile).delete();
	}
	
	@BeforeClass
	public static void configure() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}
}
