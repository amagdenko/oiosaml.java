package dk.itst.oiosaml.trust;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class RequestedSecurityTokenUnmarshaller extends TrustObjectUnmarshaller<RequestedSecurityToken> {

	@Override
	protected void processChild(RequestedSecurityToken parent, XMLObject child) throws UnmarshallingException {
        if (child instanceof Assertion) {
        	parent.getAssertions().add((Assertion) child);
        } else {
        	parent.getUnknownXMLObjects().add(child);
        }
    }
}
