package dk.itst.oiosaml.liberty;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class SecurityMechIDBuilder  extends AbstractXMLObjectBuilder<SecurityMechID> 
{

	@Override
	public SecurityMechID buildObject(String namespaceURI, String localName, String namespacePrefix) 
	{
		return new SecurityMechID(namespaceURI, localName, namespacePrefix);
	}
	
}
