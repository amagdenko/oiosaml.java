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
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */

package dk.itst.oiosaml.discovery.service;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

public class DiscoveryServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(DiscoveryServlet.class);
	
	public static final String REFERER_PARAMETER = "r";
	public static final String SAML_IDP_COOKIE = "_saml_idp";
	
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		log.info("Discovery request from " + req.getRemoteAddr() + ", referer: " + req.getParameter(REFERER_PARAMETER));
		
		if (req.getParameter(REFERER_PARAMETER) == null) {
			resp.sendError(HttpServletResponse.SC_PRECONDITION_FAILED, "The request must include a Referer (r) parameter. Unable to proceed");
			return;
		}
		
		Cookie[] cookies = req.getCookies();
		log.debug("Cookies for request: " + Arrays.toString(cookies));
		Cookie samlIdpCookie = findCookie(cookies);
		if (samlIdpCookie == null) {
			log.info("No saml idp cookie found, redirecting with empty parameter");
			sendRedirect(req.getParameter(REFERER_PARAMETER), "", resp);
		} else {
			sendRedirect(req.getParameter(REFERER_PARAMETER), samlIdpCookie.getValue(), resp);
		}
	}
	
	private void sendRedirect(String url, String cookie, HttpServletResponse res) throws IOException {
		res.setContentType("text/html");
		
		PrintWriter w = res.getWriter();
		w.write("<html><head>");
		w.write("<meta http-equiv=\"refresh\" content=\"0;url=");
		w.write(url);
		if (url.indexOf('?') > -1) {
			w.write("&_saml_idp=");
		} else {
			w.write("?_saml_idp=");
		}
		w.write(cookie);
		w.write("\">");
		w.write("</head><body></body></html>");
	}
	
	private Cookie findCookie(Cookie[] cookies) {
		for (Cookie cookie : cookies) {
			if (SAML_IDP_COOKIE.equalsIgnoreCase(cookie.getName())) {
				return cookie;
			}
		}
		return null;
	}
}
