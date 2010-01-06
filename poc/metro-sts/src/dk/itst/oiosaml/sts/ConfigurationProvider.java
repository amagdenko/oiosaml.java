package dk.itst.oiosaml.sts;

import com.sun.xml.ws.api.security.trust.config.STSConfiguration;
import com.sun.xml.ws.api.security.trust.config.STSConfigurationProvider;
import com.sun.xml.ws.security.trust.impl.DefaultSTSConfiguration;

public class ConfigurationProvider implements STSConfigurationProvider {

	@Override
	public STSConfiguration getSTSConfiguration() {
		DefaultSTSConfiguration config = new DefaultSTSConfiguration();
//		System.out.println("ConfigurationProvider.getSTSConfiguration()");
		return null;
	}

}
