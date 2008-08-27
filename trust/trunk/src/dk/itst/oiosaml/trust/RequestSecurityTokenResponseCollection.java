package dk.itst.oiosaml.trust;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;

public class RequestSecurityTokenResponseCollection extends TrustObject {

    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "RequestSecurityTokenResponseCollection"; 
    public static final QName DEFAULT_ELEMENT_NAME = XMLHelper.constructQName(TrustConstants.WST_NS, DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
    
	private List<RequestSecurityTokenResponse> responses = new ArrayList<RequestSecurityTokenResponse>();
	
	protected RequestSecurityTokenResponseCollection(String namespaceURI, String elementLocalName, String namespacePrefix)  {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
	
	@Override
	protected List<XMLObject> buildOrderedChildren() {
		List<XMLObject> res = new ArrayList<XMLObject>();
		res.addAll(responses);
		return res;
	}
    
	public List<RequestSecurityTokenResponse> getResponses() {
		return responses;
	}

}
