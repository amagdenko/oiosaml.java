/**
 * 
 */
package dk.itst.oiosaml.trust;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class RequestSecurityTokenResponseCollectionUnmarshaller extends TrustObjectUnmarshaller<RequestSecurityTokenResponseCollection> {

	@Override
	protected void processChild(RequestSecurityTokenResponseCollection parent, XMLObject child) throws UnmarshallingException {
        if (child instanceof RequestSecurityTokenResponse) {
        	parent.getResponses().add((RequestSecurityTokenResponse) child);
        } else {
        	parent.getUnknownXMLObjects().add(child);
        }
    }
}