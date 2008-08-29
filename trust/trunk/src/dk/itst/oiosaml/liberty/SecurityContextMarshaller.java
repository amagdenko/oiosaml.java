package dk.itst.oiosaml.liberty;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.AbstractXMLObjectMarshaller;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Element;

public class SecurityContextMarshaller  extends AbstractXMLObjectMarshaller
{

	@Override
	protected void marshallAttributes(XMLObject xmlObject, Element domElement) throws MarshallingException 
	{
		// NO ATTS
	}

	@Override
	protected void marshallElementContent(XMLObject xmlObject, Element domElement) throws MarshallingException 
	{
		// NO TEXT CONTENT
	}

}



