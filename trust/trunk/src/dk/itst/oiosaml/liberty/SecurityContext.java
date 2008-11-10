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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.ElementExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.signature.AbstractSignableXMLObject;
import org.opensaml.xml.util.IndexedXMLObjectChildrenList;
import org.opensaml.xml.util.XMLObjectChildrenList;

public class SecurityContext extends AbstractSignableXMLObject implements ElementExtensibleXMLObject
{

		public static String LOCAL_NAME = "SecurityContext";
	    public final static QName ELEMENT_NAME= new QName(LibertyConstants.DISCO_NS, LOCAL_NAME, LibertyConstants.DISCO_PREFIX);

				
	    private XMLObjectChildrenList<SecurityMechID> securityMechIDs;
	    private XMLObjectChildrenList<Token> tokens;
	    private IndexedXMLObjectChildrenList<XMLObject> unknownXMLObjects;
		
	    
	    public SecurityContext() 
	    {
	        super(LibertyConstants.DISCO_NS, SecurityContext.LOCAL_NAME, LibertyConstants.DISCO_PREFIX);
	    }
		
	    protected SecurityContext(String namespaceURI, String elementLocalName, String namespacePrefix)
	    {
			super(namespaceURI, elementLocalName, namespacePrefix);
			securityMechIDs = new XMLObjectChildrenList<SecurityMechID>(this);
			tokens = new XMLObjectChildrenList<Token>(this);
			unknownXMLObjects = new IndexedXMLObjectChildrenList<XMLObject>(this);
		}	
	    
	    public List<SecurityMechID> getSecurityMechIDs()
	    {
	        if(null==securityMechIDs) securityMechIDs = new XMLObjectChildrenList<SecurityMechID>(this);
	    	return securityMechIDs;
	    }	    
	    
	    public List<Token> getTokens()
	    {
	    	return tokens;
	    }
	    
	    
		public List<XMLObject> getUnknownXMLObjects()
		{
			return unknownXMLObjects;
		}	
		
	    @SuppressWarnings("unchecked")
	    public List<XMLObject> getUnknownXMLObjects(QName typeOrName)
	    {
	        return (List<XMLObject>) unknownXMLObjects.subList(typeOrName);
	    }
        
	    public List<XMLObject> getOrderedChildren()
		{
	        List<XMLObject> children = new LinkedList<XMLObject>();
	        children.addAll(securityMechIDs);
	        children.addAll(tokens);
	        children.addAll(unknownXMLObjects);
	        return Collections.unmodifiableList(children);
		}



}
