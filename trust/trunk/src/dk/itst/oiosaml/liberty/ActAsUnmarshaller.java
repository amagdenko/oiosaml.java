package dk.itst.oiosaml.liberty;

import org.opensaml.ws.wstrust.impl.AbstractWSTrustObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class ActAsUnmarshaller extends AbstractWSTrustObjectUnmarshaller {

    protected void processChildElement(XMLObject parentXMLObject, XMLObject childXMLObject)  throws UnmarshallingException {
        ActAs obo = (ActAs) parentXMLObject;
        obo.setUnknownXMLObject(childXMLObject);
    }

}
