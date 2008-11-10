/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Trust Client.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
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
