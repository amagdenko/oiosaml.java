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

	/*
 		<ds:SecurityContext>
			<ds:SecurityMechID>urn:liberty:security:2005-02:TLS:SAML</ds:SecurityMechID>
 			<sec:Token><!-- some security token goes here --></sec:Token>
 		</ds:SecurityContext>
	*/
	
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
