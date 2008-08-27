package dk.itst.oiosaml.trust;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class RequestedSecurityTokenBuilder extends AbstractXMLObjectBuilder<RequestedSecurityToken> {

	public RequestedSecurityToken buildObject() {
		return buildObject(TrustConstants.WST_NS, RequestedSecurityToken.DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
	}

	@Override
	public RequestedSecurityToken buildObject(String namespaceURI, String localName, String namespacePrefix) {
		return new RequestedSecurityToken(namespaceURI, localName, namespacePrefix);
	}
}
