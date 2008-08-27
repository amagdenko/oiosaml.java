package dk.itst.oiosaml.trust;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class KeyIdentifierBuilder extends AbstractXMLObjectBuilder<KeyIdentifier> {

	@Override
	public KeyIdentifier buildObject(String namespaceURI, String localName, String namespacePrefix) {
		return new KeyIdentifier(namespaceURI, localName, namespacePrefix);
	}
}
