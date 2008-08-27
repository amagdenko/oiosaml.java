package dk.itst.oiosaml.trust;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;

public class RequestSecurityTokenResponse extends TrustObject {

    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "RequestSecurityTokenResponse"; 
    public static final QName DEFAULT_ELEMENT_NAME = XMLHelper.constructQName(TrustConstants.WST_NS, DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
    
	private String tokenType;
	private String appliesTo;
	
	private RequestedSecurityToken requestedToken;
	
	
	protected RequestSecurityTokenResponse(String namespaceURI, String elementLocalName, String namespacePrefix) 
	{
		super(namespaceURI, elementLocalName, namespacePrefix);
	}

	@Override
	protected List<XMLObject> buildOrderedChildren() {
		List<XMLObject> children = new ArrayList<XMLObject>();
		if (requestedToken != null) {
			children.add(requestedToken);
		}
		return children;
	}
    
	public String getTokenType() {
		return tokenType;
	}


	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}


	public String getAppliesTo() {
		return appliesTo;
	}


	public void setAppliesTo(String appliesTo) {
		this.appliesTo = appliesTo;
	}

	public void setRequestedToken(RequestedSecurityToken requestedToken) {
		this.requestedToken = requestedToken;
	}
	
	public RequestedSecurityToken getRequestedToken() {
		return requestedToken;
	}
}
