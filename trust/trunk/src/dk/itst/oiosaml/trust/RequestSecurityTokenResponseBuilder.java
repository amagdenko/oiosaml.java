package dk.itst.oiosaml.trust;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class RequestSecurityTokenResponseBuilder extends AbstractXMLObjectBuilder<RequestSecurityTokenResponse> {

	public RequestSecurityTokenResponse buildObject() {
		return buildObject(TrustConstants.WST_NS, RequestSecurityTokenResponse.DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
	}

	@Override
	public RequestSecurityTokenResponse buildObject(String namespaceURI, String localName, String namespacePrefix) {
		return new RequestSecurityTokenResponse(namespaceURI, localName, namespacePrefix);
	}
}
