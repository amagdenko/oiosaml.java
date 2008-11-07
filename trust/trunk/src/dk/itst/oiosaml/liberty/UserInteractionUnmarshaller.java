package dk.itst.oiosaml.liberty;

import javax.xml.namespace.QName;

import org.opensaml.xml.AbstractElementExtensibleXMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Attr;

public class UserInteractionUnmarshaller extends AbstractElementExtensibleXMLObjectUnmarshaller
{

	@Override
	protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {
		UserInteraction ui = (UserInteraction) xmlObject;
		
		if (attribute.getName().equals("interact")) {
			ui.setInteract(attribute.getValue());
		} else if (attribute.getName().equals("redirect")) {
			ui.setRedirect(Boolean.valueOf(attribute.getValue()));
		} else {
			QName attrQName = new QName(attribute.getNamespaceURI(), attribute.getLocalName(), attribute.getPrefix());
	        if (attribute.isId()) {
	            ui.getUnknownAttributes().registerID(attrQName);
	        }
			ui.getUnknownAttributes().put(attrQName, attribute.getValue());
		}
	}
}
