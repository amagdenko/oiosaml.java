package dk.itst.oiosaml.liberty;

import javax.xml.namespace.QName;

import org.opensaml.xml.AbstractExtensibleXMLObject;

public class UserInteraction extends AbstractExtensibleXMLObject
{

		public static final String LOCAL_NAME = "UserInteraction";
	    public static final QName ELEMENT_NAME= new QName(LibertyConstants.SB_NS, LOCAL_NAME, LibertyConstants.SB_PREFIX);
	    
	    private static final QName ATTRIBUTE_INTERACT = new QName("interact");
	    private static final QName ATTRIBUTE_REDIRECT = new QName("redirect");
				
	    public UserInteraction() 
	    {
	        super(LibertyConstants.SB_NS, UserInteraction.LOCAL_NAME, LibertyConstants.SB_PREFIX);
	    }
		
	    protected UserInteraction(String namespaceURI, String elementLocalName, String namespacePrefix)
	    {
			super(namespaceURI, elementLocalName, namespacePrefix);
		}	
	    
	    public String getInteract() {
	    	return getUnknownAttributes().get(ATTRIBUTE_INTERACT);
	    }
	    
	    public void setInteract(String interact) {
	    	getUnknownAttributes().put(ATTRIBUTE_INTERACT, interact);
	    }
	    
	    public boolean redirect() {
	    	return Boolean.valueOf(getUnknownAttributes().get(ATTRIBUTE_REDIRECT));
	    }
	    
	    public void setRedirect(boolean redirect) {
	    	getUnknownAttributes().put(ATTRIBUTE_REDIRECT, Boolean.toString(redirect));
	    }
}
