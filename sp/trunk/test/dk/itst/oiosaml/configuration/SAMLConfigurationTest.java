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
 *   Aage Nielsen <ani@openminds.dk> 
 *
 */
package dk.itst.oiosaml.configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import dk.itst.oiosaml.sp.service.util.Constants;

public class SAMLConfigurationTest {

	@Before
	public void before() {
	}

	@Test(expected = IllegalStateException.class)
	public void failOnMissingSystemProperty() {
		SAMLConfigurationFactory.getConfiguration().getSystemConfiguration();
	}

	@Test
	public void testIsConfigured() throws Exception {

		SAMLConfiguration sc = SAMLConfigurationFactory.getConfiguration();
		Map<String, String> params = new HashMap<String, String>();
		sc.setInitConfiguration(params);
		assertFalse(sc.isConfigured());

		final File dir = new File(File.createTempFile("test", "test").getAbsolutePath() + ".home");
		dir.mkdir();

		File content = new File(dir, "oiosaml-sp.properties");

		FileOutputStream fos = new FileOutputStream(content);
		fos.write("testing=more\noiosaml-sp.servlet=test".getBytes());
		fos.close();

		params.put(Constants.INIT_OIOSAML_HOME, dir.getAbsolutePath());
		params.put(Constants.INIT_OIOSAML_NAME, "oiosaml-sp.properties");
		sc.setInitConfiguration(params);
		assertTrue(sc.isConfigured());

		assertEquals("more", sc.getSystemConfiguration().getString("testing"));
		assertEquals("test", sc.getSystemConfiguration().getString("oiosaml-sp.servlet"));
		assertEquals("oiosaml-sp.log4j.xml", sc.getSystemConfiguration().getString("oiosaml-sp.log"));

		content.delete();
		dir.delete();
	}
}
