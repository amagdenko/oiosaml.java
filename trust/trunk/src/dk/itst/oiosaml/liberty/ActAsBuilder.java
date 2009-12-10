package dk.itst.oiosaml.liberty;

import org.opensaml.ws.wstrust.impl.AbstractWSTrustObjectBuilder;

public class ActAsBuilder extends AbstractWSTrustObjectBuilder<ActAs> {

    /** {@inheritDoc} */
    public ActAs buildObject() {
        return buildObject(ActAs.ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    public ActAs buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new ActAs(namespaceURI, localName, namespacePrefix);
    }

}
