package dk.itst.oiosaml.liberty;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.xml.AbstractXMLObjectBuilder;
import org.opensaml.xml.ElementExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.AbstractXMLObjectMarshaller;
import org.opensaml.xml.io.AbstractXMLObjectUnmarshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.signature.AbstractSignableXMLObject;
import org.opensaml.xml.util.IndexedXMLObjectChildrenList;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

/**
 * <pre>
 * &lt;xs:complexType name="TokenType"&gt;
 *   &lt;xs:sequence&gt;
 *     &lt;xs:any namespace="##any" processContents="lax" 
 *             minOccurs="0" maxOccurs="unbounded"/&gt;
 *   &lt;/xs:sequence&gt;
 *   &lt;xs:attribute name="id" type="xs:ID" use="optional" /&gt;
 *   &lt;xs:attribute name="ref" type="xs:anyURI" use="optional" /&gt;
 *   &lt;xs:attribute name="usage" type="xs:anyURI" use="optional" /&gt;
 * &lt;/xs:complexType&gt;
 * 
 * &lt;xs:element name="Token" type="sec:TokenType" /&gt;
 * </pre>
 * @author asa
 *
 */
public class Token extends AbstractSignableXMLObject implements ElementExtensibleXMLObject
{
    
    // Element Content
    private String value;       
    
    // Attribute Names
    public static String LOCAL_NAME = "Token";
    public static String ATT_REF = "ref";
    public static String ATT_USAGE = "usage";
    public static String ATT_ID = "id";
    
    // Attributes
    private String id;
    private String ref;
    private String usage;   // TagetId, InvocationId, or SecToken
    
    // Elements
    private Assertion assertion;
    private EncryptedAssertion encryptedAssertion;  
    private IndexedXMLObjectChildrenList<XMLObject> unknownXMLObjects;
    
    
    public Token() 
    {
        super(LibertyConstants.SEC_NS, LOCAL_NAME, LibertyConstants.SEC_PREFIX);
    }
    
    protected Token(String namespaceURI, String elementLocalName, String namespacePrefix) 
    {       
        super(namespaceURI, elementLocalName, namespacePrefix);
        unknownXMLObjects = new IndexedXMLObjectChildrenList<XMLObject>(this);      
    }
    
    public String getRef() 
    { 
        return ref; 
    }

    public void setRef(String ref) 
    {
        this.ref = prepareForAssignment(this.ref, ref);
    }

    public String getUsage() 
    { 
        return usage; 
    }

    public void setUsage(String usage) 
    {
        this.usage = prepareForAssignment(this.usage, usage);
    }
    
    public String getId() 
    {
        return id;
    }
    
    public void setId(String id) 
    {
        registerOwnID(this.id, id);
        this.id = id;
    }   

    public Assertion getAssertion()
    {
        return assertion;
    }

    public void setAssertion(Assertion assertion)
    {
        this.assertion = assertion;
    }

    public EncryptedAssertion getEncryptedAssertion()
    {
        return encryptedAssertion;
    }

    public void setEncryptedAssertion(EncryptedAssertion encryptedAssertion)
    {
        this.encryptedAssertion = encryptedAssertion;
    }

    
    public void setValue(String value) 
    {
        this.value = prepareForAssignment(this.value, value);
    }
        
    public String getValue() 
    { 
        return value; 
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
        children.add(assertion);
        children.add(encryptedAssertion);
        children.addAll(unknownXMLObjects);
        return Collections.unmodifiableList(children);
    }

    /**
     * Static Builder
     * 
     * @author asa
     *
     */
    public static class Builder extends AbstractXMLObjectBuilder<Token> 
    {

        @Override
        public Token buildObject(String namespaceURI, String localName, String namespacePrefix) 
        {
            return new Token(namespaceURI, localName, namespacePrefix);
        }

    }

    
    /**
     * Static Marshaller
     * 
     * @author asa
     *
     */
    public static class Marshaller extends AbstractXMLObjectMarshaller
    {

        @Override
        protected void marshallAttributes(XMLObject xmlObject, Element domElement) throws MarshallingException 
        {
            Token token = (Token) xmlObject;
            
            if(token.getId() != null)
            {
                domElement.setAttributeNS(null, Token.ATT_ID, token.getId());
                domElement.setIdAttributeNS(null, Token.ATT_ID, true);
            }
            
            if(token.getRef() != null)
            {
                domElement.setAttributeNS(null, Token.ATT_REF, token.getRef());
            }

            if(token.getUsage() != null)
            {
                domElement.setAttributeNS(null, Token.ATT_USAGE, token.getUsage());
            }
                    
            
        }

        @Override
        protected void marshallElementContent(XMLObject xmlObject, Element domElement) throws MarshallingException 
        {
            Token token = (Token) xmlObject;
            XMLHelper.appendTextContent(domElement, token.getValue());          
        }

    }

    /**
     * Static Unmarshaller
     * 
     * @author asa
     *
     */
    public static class Unmarshaller extends AbstractXMLObjectUnmarshaller
    {

        @Override
        protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException 
        {
            Token token = (Token) xmlObject;

            if (attribute.getLocalName().equals(Token.ATT_REF)) 
            {
                token.setRef(attribute.getValue());
            }
            else if (attribute.getLocalName().equals(Token.ATT_ID)) 
            {
                token.setId(attribute.getValue());
                attribute.getOwnerElement().setIdAttributeNode(attribute, true);
            }        
            else if (attribute.getLocalName().equals(Token.ATT_USAGE)) 
            {
                token.setUsage(attribute.getValue());
            }
        }

        @Override
        protected void processChildElement(XMLObject parentXMLObject, XMLObject childXMLObject) throws UnmarshallingException 
        {
            Token token = (Token) parentXMLObject;

            if(childXMLObject instanceof Assertion) 
            {
                token.setAssertion((Assertion)childXMLObject);
            }
            else if(childXMLObject instanceof EncryptedAssertion) 
            {
                token.setEncryptedAssertion((EncryptedAssertion)childXMLObject);
            }            
            else 
            {
                token.getUnknownXMLObjects().add(childXMLObject);
            }
        }

        @Override
        protected void processElementContent(XMLObject xmlObject, String elementContent) 
        {
            // NO CONTENT
        }

    }


    

}
