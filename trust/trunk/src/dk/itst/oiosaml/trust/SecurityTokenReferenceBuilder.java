package dk.itst.oiosaml.trust;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class SecurityTokenReferenceBuilder extends AbstractXMLObjectBuilder<SecurityTokenReference> {

	@Override
	public SecurityTokenReference buildObject(String namespaceURI, String localName, String namespacePrefix) {
		return new SecurityTokenReference(namespaceURI, localName, namespacePrefix);
	}
}
