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
