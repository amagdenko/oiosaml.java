package dk.itst.oiosaml.authz;

import java.io.File;
import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import dk.itst.oiosaml.configuration.BRSConfiguration;
import dk.itst.oiosaml.sp.OIOPrincipal;
import dk.itst.oiosaml.sp.UserAttribute;

public class AuthzFilter implements Filter {
	private static final Logger log = Logger.getLogger(AuthzFilter.class);
	private Protections protections;
	private Authorisations NO_AUTHS = new Authorisations("<Authorisations xmlns=\"http://www.eogs.dk/2007/07/brs\"></Authorisations>");

	public void destroy() {
		protections = null;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain fc) throws IOException, ServletException {
		HttpServletRequest r = (HttpServletRequest) req;
		
		OIOPrincipal p = (OIOPrincipal) r.getUserPrincipal();
		if (p == null) {
			String msg = "No UserAssertion in request. Please make sure this filter is defined after the OIOSAML.java protection filter";
			log.fatal(msg);
			throw new ServletException(msg);
		}
		UserAttribute auths = p.getAssertion().getAttribute(Constants.AUTHORISATIONS_ATTRIBUTE);
		Authorisations authorisations;
		if (auths == null) {
			authorisations = NO_AUTHS;
		} else {
			authorisations = new Authorisations(auths.getValue());
		}
		
		String resource = extractResource(p);
		if (resource == null) {
			log.error("User does not have cvr or " + Constants.PRODUCTION_CODE_ATTRIBUTE + " attribute in assertion. Denying access");
			denyAccess((HttpServletResponse) res);
			return;
		}

		String url = r.getRequestURI().substring(r.getContextPath().length());
		if (log.isDebugEnabled()) log.debug("Checking access to " + url + " for user " + p.getName());
		
		if (protections.isAuthorised(resource, url, r.getMethod(), authorisations)) {
			log.debug("Access granted to " + url + " granted to " + p.getName());
			fc.doFilter(req, res);
			return;
		} else {
			log.error("Access to "  + url +  " denied for user " + p.getName());
			denyAccess((HttpServletResponse) res);
			return;
		}
	}
	
	private void denyAccess(HttpServletResponse res) throws IOException {
		res.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied to the requested resource");
	}

	public void init(FilterConfig arg0) throws ServletException {
		log.info("Initializing OIOSAML AuthzFilter");

		try {
			Configuration cfg = BRSConfiguration.getSystemConfiguration();
			String configFile = BRSConfiguration.getStringPrefixedWithBRSHome(cfg, Constants.PROP_PROTECTION_CONFIG_FILE);
			setConfiguration(configFile);
		} catch (IllegalStateException e) {
			String msg = "No OIOSAML.java configuration found! Please ensure that this filter is loaded after the OIOSAML.java filter";
			log.fatal(msg, e);
			throw new ServletException(msg);
		}
	}
	
	public void setConfiguration(String configFile) throws ServletException {
		try {
			log.info("Reading authz config from " + configFile);
			String xml = FileUtils.readFileToString(new File(configFile));

			protections = new Protections(xml);
		} catch (IOException e) {
			log.fatal("Unable to read config file", e);
			throw new ServletException("Unable to read config file", e);
		}
	}

	private String extractResource(OIOPrincipal p) {
		String resource = null;
		String cvr = p.getAssertion().getCVRNumberIdentifier();
		if (cvr != null) {
			resource = Constants.RESOURCE_CVR_NUMBER_PREFIX + cvr;
		} else {
			UserAttribute pcode = p.getAssertion().getAttribute(Constants.PRODUCTION_CODE_ATTRIBUTE);
			if (pcode != null) {
				resource = Constants.RESOURCE_PNUMER_PREFIX + pcode.getValue();
			}
		}
		
		return resource;
	}

}
