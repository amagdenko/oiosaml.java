package dk.itst.oiosaml.liberty;

import java.util.Map.Entry;

import javax.xml.namespace.QName;

import org.opensaml.xml.AbstractElementExtensibleXMLObjectMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class UserInteractionMarshaller  extends AbstractElementExtensibleXMLObjectMarshaller
{

	@Override
	protected void marshallAttributes(XMLObject xmlObject, Element domElement) throws MarshallingException {
		UserInteraction ui = (UserInteraction) xmlObject;
		
		if (ui.getInteract() != null) {
			domElement.setAttribute("interact", ui.getInteract());
		}
		domElement.setAttribute("redirect", Boolean.toString(ui.redirect()));
		
        Document document = domElement.getOwnerDocument();
        Attr attribute;
        for (Entry<QName, String> entry : ui.getUnknownAttributes().entrySet()) {
            attribute = XMLHelper.constructAttribute(document, entry.getKey());
            attribute.setValue(entry.getValue());
            domElement.setAttributeNodeNS(attribute);
        }
	}
}
