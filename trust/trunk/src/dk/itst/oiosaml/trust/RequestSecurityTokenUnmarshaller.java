/**
 * 
 */
package dk.itst.oiosaml.trust;

import javax.xml.namespace.QName;

import org.openliberty.xmltooling.Konstantz;
import org.openliberty.xmltooling.wsa.EndpointReference;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.util.XMLHelper;

public class RequestSecurityTokenUnmarshaller extends TrustObjectUnmarshaller<RequestSecurityToken> {
	private static final QName ENDPOINT_NAME = XMLHelper.constructQName(Konstantz.WSA_NS, EndpointReference.LOCAL_NAME, Konstantz.WSA_PREFIX);
	
	@Override
	protected void processChild(RequestSecurityToken security, XMLObject childXMLObject) throws UnmarshallingException {
        if (childXMLObject instanceof XSAny) {
        	XSAny xa = (XSAny) childXMLObject;
        	if (TrustConstants.WST_NS.equals(xa.getElementQName().getNamespaceURI()) && 
        			"TokenType".equals(xa.getElementQName().getLocalPart())) {
        		security.setTokenType(xa.getTextContent());
        		return;
        	} else if (TrustConstants.WST_NS.equals(xa.getElementQName().getNamespaceURI()) && 
        			"RequestType".equals(xa.getElementQName().getLocalPart())) {
        		security.setRequestType(xa.getTextContent());
        		return;
        	}  else if (TrustConstants.WST_NS.equals(xa.getElementQName().getNamespaceURI()) && 
        			"OnBehalfOf".equals(xa.getElementQName().getLocalPart())) {
        		SecurityTokenReference ref = (SecurityTokenReference) xa.getUnknownXMLObjects(SecurityTokenReference.DEFAULT_ELEMENT_NAME).get(0);
        		security.setOnBehalfOf(ref);
        		return;
        	} else if (TrustConstants.WSP_NS.equals(xa.getElementQName().getNamespaceURI()) && 
        			"AppliesTo".equals(xa.getElementQName().getLocalPart())) {
        		EndpointReference ref = (EndpointReference) xa.getUnknownXMLObjects(ENDPOINT_NAME).get(0);
        		security.setAppliesTo(ref.getAddress().getValue());
        	} else if (TrustConstants.WST_NS.equals(xa.getElementQName().getNamespaceURI()) && 
        			"Issuer".equals(xa.getElementQName().getLocalPart())) {
        		EndpointReference ref = (EndpointReference) xa.getUnknownXMLObjects(ENDPOINT_NAME).get(0);
        		security.setIssuer(ref.getAddress().getValue());
        	}
        } else if (childXMLObject instanceof EndpointReference) {
        	
        	return;
        }
        security.getUnknownXMLObjects().add(childXMLObject);
    }

}