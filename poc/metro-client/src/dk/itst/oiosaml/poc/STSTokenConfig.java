package dk.itst.oiosaml.poc;

import com.sun.xml.ws.security.trust.impl.client.DefaultSTSIssuedTokenConfiguration;

public class STSTokenConfig extends DefaultSTSIssuedTokenConfiguration {

	@Override
	public String getSTSEndpoint() {
		return "http://localhost:8081/sts/TokenService";
	}
	
	@Override
	public String getSTSWSDLLocation() {
		return "http://localhost:8081/sts/wsdl";
	}
	
	@Override
	public String getSTSMEXAddress() {
		return null;
	}
	
	@Override
	public String getSTSNamespace() {
		return "http://tempuri.org/";
	}
	
	@Override
	public String getSTSPortName() {
		return "STSService";
	}
	
	@Override
	public String getSTSServiceName() {
		return "STSService";
	}
	
}
