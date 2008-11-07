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
