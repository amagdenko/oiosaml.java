package dk.itst.oiosaml.trust;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class RequestSecurityTokenResponseCollectionBuilder extends AbstractXMLObjectBuilder<RequestSecurityTokenResponseCollection> {

	public RequestSecurityTokenResponseCollection buildObject() {
		return buildObject(TrustConstants.WST_NS, RequestSecurityTokenResponseCollection.DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
	}

	@Override
	public RequestSecurityTokenResponseCollection buildObject(String namespaceURI, String localName, String namespacePrefix) {
		return new RequestSecurityTokenResponseCollection(namespaceURI, localName, namespacePrefix);
	}
}
