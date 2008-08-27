package dk.itst.oiosaml.trust;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class RequestSecurityTokenResponseUnmarshaller extends TrustObjectUnmarshaller<RequestSecurityTokenResponse> {

	@Override
	protected void processChild(RequestSecurityTokenResponse parent, XMLObject child) throws UnmarshallingException {
        if (child instanceof RequestedSecurityToken) {
        	parent.setRequestedToken((RequestedSecurityToken) child);
        } else {
        	parent.getUnknownXMLObjects().add(child);
        }
    }
}