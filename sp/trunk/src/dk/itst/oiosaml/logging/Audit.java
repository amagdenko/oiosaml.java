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
 * created by Trifork A/S are Copyright (C) 2009 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.logging;

import java.io.File;
import java.text.MessageFormat;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;

import dk.itst.oiosaml.sp.UserAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;

public class Audit {
	private static Logger log = Logger.getLogger("OIOSAML_AUDIT_LOGGER");
	
	private static final ThreadLocal<MessageFormat> format = new ThreadLocal<MessageFormat>() {
		protected MessageFormat initialValue() {
			// format: operation direction "remote session 'assertion' 'data' 'message'"
			return new MessageFormat("{0} {1,choice,-1#---|0#-->|1#'<'--} {2} {3} ''{4}'' ''{5}'' ''{6}''");
		}
	};

	private static final ThreadLocal<String> remoteAddress = new ThreadLocal<String>();
	private static final ThreadLocal<String> session = new ThreadLocal<String>();
	private static final ThreadLocal<String> assertionId = new ThreadLocal<String>() {
		protected String initialValue() {
			return "";
		}
	};

	public static void log(Operation operation, String msg) {
		logEntry(operation.name(), null, "", msg);
	}
	
	public static void log(Operation operation, boolean out, String id, String request) {
		if (id != null && !"".equals(id)) {
			logEntry(operation.name(), out, request, "RequestID " + id);
		} else {
			logEntry(operation.name(), out, request, "");
		}
	}

	private static void logEntry(String operation, Boolean out, String data, String msg) {
		int dir = getDirection(out);
		if (msg == null) msg = "";
		String entry = format.get().format(new Object[] {operation, dir, remoteAddress.get(), session.get(), assertionId.get(), data, msg.replace('\n', ' ') });
		log.info(entry);
	}


	
	public static void logError(Operation operation, boolean out, String id, Throwable t) {
		logError(operation.name(), out, t.getMessage(), t);
	}
	
	public static void logError(String action, boolean b, Exception e) {
		logError("Dispatch:" + action, b, e.getMessage(), e);
	}

	public static void logError(Operation operation, boolean out, String id, String error) {
		logError(operation.name(), out, error, null);
	}
	
	private static void logError(String operation, Boolean out, String msg, Throwable e) {
		String entry = format.get().format(new Object[] {operation, getDirection(out), remoteAddress.get(), session.get(), assertionId.get(), "", msg });
		log.error(entry, e);
	}
	

	private static int getDirection(Boolean out) {
		int dir;
		if (out == null) {
			dir = -1;
		} else if (out) {
			dir = 0;
		} else {
			dir = 1;
		}
		return dir;
	}

	public static void init(HttpServletRequest request) {
		remoteAddress.set(request.getRemoteAddr());
		session.set(request.getSession().getId());
		
		UserAssertion ua = (UserAssertion) request.getSession().getAttribute(Constants.SESSION_USER_ASSERTION);
		if (ua != null) {
			assertionId.set(ua.getAssertionId());
		} else {
			assertionId.set("");
		}
	}

	/**
	 * Initialize log4j with the specified configuration file.
	 * 
	 * @param xmlFilename
	 *            The log4j configuration file. It must be in xml format, since
	 *            the DomConfigurator is used unconditionally. An absolute path is expected.
	 */
	public static void configureLog4j(final String xmlFilename) {
		System.out.println("Configuring logging from " + xmlFilename);
		try {
			new DOMConfigurator() {
				@Override
				protected String subst(String value) {
					return value.replaceAll("\\$\\{oiosaml.home\\}", new File(xmlFilename).getParent());
				}
			}.doConfigure(xmlFilename, LogManager.getLoggerRepository());
		} catch (Exception e) {
			log.error("Unable to configure logging from " + xmlFilename, e);
		}
	}



}
