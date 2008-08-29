package dk.itst.oiosaml.liberty;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class SecurityContextBuilder extends AbstractXMLObjectBuilder<SecurityContext> 
{

	@Override
	public SecurityContext buildObject(String namespaceURI, String localName, String namespacePrefix) 
	{
		return new SecurityContext(namespaceURI, localName, namespacePrefix);
	}

}
