package dk.itst.oiosaml.liberty;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.ws.wstrust.impl.AbstractWSTrustObject;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.trust.TrustConstants;

public class ActAs extends AbstractWSTrustObject {
    /** Element local name. */
    public static final String ELEMENT_LOCAL_NAME = "ActAs";

    /** Default element name. */
    public static final QName ELEMENT_NAME =
        new QName(TrustConstants.WST14_NS, ELEMENT_LOCAL_NAME, TrustConstants.WST14_PREFRIX);
    

    /** Wildcard child element. */
    private XMLObject unknownChild;

    /**
     * Constructor.
     * 
     * @param namespaceURI The namespace of the element
     * @param elementLocalName The local name of the element
     * @param namespacePrefix The namespace prefix of the element
     */
    public ActAs(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /** {@inheritDoc} */
    public XMLObject getUnknownXMLObject() {
        return unknownChild;
    }

    /** {@inheritDoc} */
    public void setUnknownXMLObject(XMLObject unknownObject) {
        unknownChild = prepareForAssignment(unknownChild, unknownObject);
    }

    /** {@inheritDoc} */
    public List<XMLObject> getOrderedChildren() {
        List<XMLObject> children = new ArrayList<XMLObject>();
        if (unknownChild != null) {
            children.add(unknownChild);
        }
        return Collections.unmodifiableList(children);
    }

}
