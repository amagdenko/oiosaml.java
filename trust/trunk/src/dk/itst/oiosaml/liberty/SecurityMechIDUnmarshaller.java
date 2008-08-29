package dk.itst.oiosaml.liberty;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.AbstractXMLObjectUnmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Attr;

public class SecurityMechIDUnmarshaller extends AbstractXMLObjectUnmarshaller
{

	@Override
	protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException 
	{
		// NO ATTS
	}

	@Override
	protected void processChildElement(XMLObject parentXMLObject, XMLObject childXMLObject) throws UnmarshallingException 
	{
		// NO CHILDREN
	}

	@Override
	protected void processElementContent(XMLObject xmlObject, String elementContent) 
	{
		SecurityMechID securityMechID = (SecurityMechID) xmlObject;
		securityMechID.setValue(elementContent);
	}
	
}
