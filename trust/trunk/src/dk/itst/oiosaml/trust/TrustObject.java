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

import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.ElementExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.AbstractSignableXMLObject;
import org.opensaml.xml.util.AttributeMap;
import org.opensaml.xml.util.IndexedXMLObjectChildrenList;

public class TrustObject extends AbstractSignableXMLObject implements ElementExtensibleXMLObject, AttributeExtensibleXMLObject {

	/**
	 * Support for ElementExtensibleXMLObject interface
	 */
	protected final IndexedXMLObjectChildrenList<XMLObject> unknownChildren;
	
	/**
	 * Support for AttributeExtensibleXMLObject interface
	 */
	protected final AttributeMap otherAttributes;
	
	protected TrustObject(String namespaceURI, String elementLocalName, String namespacePrefix) 
	{
		super(namespaceURI, elementLocalName, namespacePrefix);
		unknownChildren = new IndexedXMLObjectChildrenList<XMLObject>(this);
		otherAttributes = new AttributeMap(this);
	}

	public final List<XMLObject> getUnknownXMLObjects() 
	{
		return unknownChildren;
	}

    @SuppressWarnings("unchecked")
    public final List<XMLObject> getUnknownXMLObjects(QName typeOrName)
    {
        return (List<XMLObject>) unknownChildren.subList(typeOrName);
    }
    
	public final List<XMLObject> getOrderedChildren() 
	{
		return Collections.unmodifiableList(buildOrderedChildren());
	}
    
	public final AttributeMap getUnknownAttributes() 
	{
		return otherAttributes;
	}
	
	protected List<XMLObject> buildOrderedChildren() {
		return unknownChildren;
	}
	
}
