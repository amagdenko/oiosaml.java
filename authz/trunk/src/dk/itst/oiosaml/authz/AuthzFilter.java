/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Authz
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
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

import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.sp.OIOPrincipal;
import dk.itst.oiosaml.sp.UserAttribute;

/**
 * OIOSAML Authorisation filter.
 * 
 * <p>This filter checks if an OIOSAML authenticated user has permission to access the requested url. The filter relies on a
 * configuration file, which must be defined in the general properties file. A property named {@link Constants#PROP_PROTECTION_CONFIG_FILE} must
 * point to the access configuration file.</p>
 * 
 * <p>If a property in the general properties file named {@link Constants#PROP_PROTECTION_ERROR_SERVLET} is defined, users will
 * be redirected to this servlet if access is denied. This makes it possible to add custom error pages.</p>
 * 
 * <p>The filter must be defined after the OIOSAML SPFilter. If the user does not have a CVR number or a production unit id, access will be
 * denied immediately.</p>
 * 
 * @author recht
 *
 */
public class AuthzFilter implements Filter {
	private static final Logger log = Logger.getLogger(AuthzFilter.class);
	
	private Authz authz;

	public void destroy() {
		Authz.setProtections(null);
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain fc) throws IOException, ServletException {
		HttpServletRequest r = (HttpServletRequest) req;
		
		if (r.getServletPath().equals(SAMLConfiguration.getSystemConfiguration().getProperty(dk.itst.oiosaml.sp.service.util.Constants.PROP_SAML_SERVLET))) {
			log.debug("Request to SAML servlet, access granted");
			fc.doFilter(req, res);
			return;
		}

		OIOPrincipal p = (OIOPrincipal) r.getUserPrincipal();
		if (p == null) {
			String msg = "No UserAssertion in request. Please make sure this filter is defined after the OIOSAML.java protection filter";
			log.fatal(msg);
			throw new ServletException(msg);
		}
		
		String resource = extractResource(p);
		if (resource == null) {
			log.error("User does not have cvr or " + Constants.PRODUCTION_CODE_ATTRIBUTE + " attribute in assertion. Denying access");
			denyAccess(r, (HttpServletResponse) res);
			return;
		}

		String url = r.getRequestURI().substring(r.getContextPath().length());
		if (log.isDebugEnabled()) log.debug("Checking access to " + url + " for user " + p.getName() + ", resource " + resource);

		if (authz.hasAccess(resource, url, r.getMethod(), p.getAssertion())) {
			log.debug("Access granted to " + url + " granted to " + p.getName());
			fc.doFilter(req, res);
			return;
		} else {
			log.error("Access to "  + url +  " denied for user " + p.getName());
			denyAccess(r, (HttpServletResponse) res);
			return;
		}
	}
	
	private void denyAccess(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
		String errorServlet = SAMLConfiguration.getSystemConfiguration().getString(Constants.PROP_PROTECTION_ERROR_SERVLET);
		if (errorServlet != null) {
			log.debug("Redirecting to error servlet at " + errorServlet);
			req.getRequestDispatcher(errorServlet).forward(req, res);
		} else {
			log.debug("No error servlet defined in " + Constants.PROP_PROTECTION_ERROR_SERVLET + ", sending standard error");
			res.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied to the requested resource");
		}
	}

	public void init(FilterConfig arg0) throws ServletException {
		log.info("Initializing OIOSAML AuthzFilter");

		try {
			Configuration cfg = SAMLConfiguration.getSystemConfiguration();
			String configFile = SAMLConfiguration.getStringPrefixedWithBRSHome(cfg, Constants.PROP_PROTECTION_CONFIG_FILE);
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

			Protections protections = new Protections(xml);
			Authz.setProtections(protections);
			authz = new Authz(protections);
		} catch (IOException e) {
			String msg = "Unable to read config file. Make sure that " + Constants.PROP_PROTECTION_CONFIG_FILE + " points to a valid XML file";
			log.fatal(msg, e);
			throw new ServletException(msg, e);
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
