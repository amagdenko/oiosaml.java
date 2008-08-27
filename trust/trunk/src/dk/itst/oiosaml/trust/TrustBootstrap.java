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
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.trust;

import org.apache.log4j.Logger;
import org.openliberty.wsc.OpenLibertyBootstrap;
import org.opensaml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLConfigurator;

public class TrustBootstrap {
	private static final Logger log = Logger.getLogger(TrustBootstrap.class);
	
	private static boolean bootstrapped = false;

	public static void bootstrap() {
		if (!bootstrapped) {
	        Class<Configuration> clazz = Configuration.class;
	
	        String config = "/dk/itst/oiosaml/trust/sec-config.xml";
	        if (log.isDebugEnabled())  log.debug("Loading XMLTooling configuration " + config);
	        try {
	        	OpenLibertyBootstrap.bootstrap();
	        	XMLConfigurator configurator = new XMLConfigurator();
				configurator.load(clazz.getResourceAsStream(config));
			} catch (ConfigurationException e) {
				throw new RuntimeException(e);
			}
			bootstrapped = true;
		}
	}
}