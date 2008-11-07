package dk.itst.oiosaml.liberty;

import org.opensaml.xml.AbstractXMLObjectBuilder;

public class UserInteractionBuilder  extends AbstractXMLObjectBuilder<UserInteraction> 
{

	@Override
	public UserInteraction buildObject(String namespaceURI, String localName, String namespacePrefix) 
	{
		return new UserInteraction(namespaceURI, localName, namespacePrefix);
	}
	
}
