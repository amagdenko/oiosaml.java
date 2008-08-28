package dk.itst.oiosaml.trust;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class SecurityTokenReferenceUnmarshaller extends TrustObjectUnmarshaller<SecurityTokenReference> {

	@Override
	protected void processChild(SecurityTokenReference parent, XMLObject child) throws UnmarshallingException {
        if (child instanceof KeyIdentifier) {
        	parent.setKeyIdentifier((KeyIdentifier) child);
        } else {
        	parent.getUnknownXMLObjects().add(child);
        }
    }
}
