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
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.trust;

import javax.xml.namespace.QName;

import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.AbstractXMLObjectUnmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Attr;

public class TrustObjectUnmarshaller<T extends XMLObject> extends AbstractXMLObjectUnmarshaller {

    protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {
        AttributeExtensibleXMLObject obj = (AttributeExtensibleXMLObject) xmlObject;
        QName attribQName = XMLHelper.getNodeQName(attribute);
        if (attribute.isId()) {
            obj.getUnknownAttributes().registerID(attribQName);
        }
        obj.getUnknownAttributes().put(attribQName, attribute.getValue());
    }

    
    @SuppressWarnings("unchecked")
	protected final void processChildElement(XMLObject parentXMLObject, XMLObject childXMLObject) throws UnmarshallingException {
    	processChild((T) parentXMLObject, childXMLObject);
    }
    
    protected void processChild(T parent, XMLObject child) throws UnmarshallingException {
    }
    
    protected void processElementContent(XMLObject xmlObject, String elementContent) {
    	
    }

}
