package dk.itst.oiosaml.trust;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class RequestSecurityTokenBuilder extends AbstractXMLObjectBuilder<RequestSecurityToken> {

	public RequestSecurityToken buildObject() {
		return buildObject(TrustConstants.WST_NS, RequestSecurityToken.DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
	}

	@Override
	public RequestSecurityToken buildObject(String namespaceURI, String localName, String namespacePrefix) {
		return new RequestSecurityToken(namespaceURI, localName, namespacePrefix);
	}
}
