package dk.itst.oiosaml.liberty;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.AbstractXMLObjectUnmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Attr;

public class SecurityContextUnmarshaller extends AbstractXMLObjectUnmarshaller
{

	@Override
	protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException 
	{
		// NO ATTRIBUTE
	}

	@Override
	protected void processChildElement(XMLObject parentXMLObject, XMLObject childXMLObject) throws UnmarshallingException 
	{

		SecurityContext securityContext = (SecurityContext) parentXMLObject;

        if (childXMLObject instanceof SecurityMechID) 
        {
        	securityContext.getSecurityMechIDs().add((SecurityMechID) childXMLObject);
        }
        else if (childXMLObject instanceof Token) 
        {
        	securityContext.getTokens().add((Token) childXMLObject);
        }
        else
        {
        	securityContext.getUnknownXMLObjects().add(childXMLObject);
        }

	}

	@Override
	protected void processElementContent(XMLObject xmlObject, String elementContent) 
	{
		// NO ELEMENT CONTENT
	}



}
