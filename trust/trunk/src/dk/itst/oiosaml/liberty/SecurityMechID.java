package dk.itst.oiosaml.liberty;

import java.util.List;

import org.opensaml.xml.AbstractXMLObject;
import org.opensaml.xml.XMLObject;

public class SecurityMechID extends AbstractXMLObject
{

	public static String LOCAL_NAME = "SecurityMechID";
	
	private String value;
	

    public SecurityMechID() 
    {
        super(LibertyConstants.DISCO_NS, SecurityMechID.LOCAL_NAME, LibertyConstants.DISCO_PREFIX);
    }
	
	
	protected SecurityMechID(String namespaceURI, String elementLocalName, String namespacePrefix) 
	{
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
	
    public void setValue(String value) 
    {
    	this.value = prepareForAssignment(this.value, value);
    }
    
    public String getValue() 
    { 
    	return value; 
    }
    
	public List<XMLObject> getOrderedChildren() 
	{
		return null;
	}

}
