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

import org.opensaml.xml.AbstractExtensibleXMLObject;

public class UserInteraction extends AbstractExtensibleXMLObject
{

		public static final String LOCAL_NAME = "UserInteraction";
	    public static final QName ELEMENT_NAME= new QName(LibertyConstants.SB_NS, LOCAL_NAME, LibertyConstants.SB_PREFIX);
	    
	    private String interact;
	    private boolean redirect;
				
	    public UserInteraction() 
	    {
	        super(LibertyConstants.SB_NS, UserInteraction.LOCAL_NAME, LibertyConstants.SB_PREFIX);
	    }
		
	    protected UserInteraction(String namespaceURI, String elementLocalName, String namespacePrefix)
	    {
			super(namespaceURI, elementLocalName, namespacePrefix);
		}	
	    
	    public String getInteract() {
	    	return interact;
	    }
	    
	    public void setInteract(String interact) {
			this.interact = interact;
	    }
	    
	    public boolean redirect() {
	    	return redirect;
	    }
	    
	    public void setRedirect(boolean redirect) {
			this.redirect = redirect;
	    }
}
