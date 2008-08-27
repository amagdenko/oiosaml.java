package dk.itst.oiosaml.trust;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.openliberty.xmltooling.wsa.Address;
import org.openliberty.xmltooling.wsa.EndpointReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;

public class RequestSecurityToken extends TrustObject {

	public static final String DEFAULT_ELEMENT_LOCAL_NAME = "RequestSecurityToken";
    public static final QName DEFAULT_ELEMENT_NAME = XMLHelper.constructQName(TrustConstants.WST_NS, DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
    
	private XSAnyBuilder builder = new XSAnyBuilder();
	
	private String tokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
	private String requestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
	private SecurityTokenReference onBehalfOf;
	private String appliesTo;
	private String issuer;
	
	protected RequestSecurityToken(String namespaceURI, String elementLocalName, String namespacePrefix) 
	{
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
	
	@Override
	protected List<XMLObject> buildOrderedChildren() {
		ArrayList<XMLObject> children = new ArrayList<XMLObject>();
		
		XSAnyBuilder builder = new XSAnyBuilder();

		children.add(createTextElement("TokenType", tokenType));
		children.add(createTextElement("RequestType", requestType));
		if (appliesTo != null) {
			XSAny ep = builder.buildObject(TrustConstants.WSP_NS, "AppliesTo", TrustConstants.WSP_PREFIX);
			
			EndpointReference epr = new EndpointReference();
			Address addr = new Address();
			addr.setValue(appliesTo);
			epr.setAddress(addr);
			
			ep.getUnknownXMLObjects().add(epr);
			children.add(ep);
		}
		
		if (issuer != null) {
			XSAny ep = builder.buildObject(TrustConstants.WST_NS, "Issuer", TrustConstants.WST_PREFIX);

			EndpointReference epr = new EndpointReference();
			Address addr = new Address();
			addr.setValue(issuer);
			epr.setAddress(addr);
			
			ep.getUnknownXMLObjects().add(epr);
			children.add(ep);
		}
		
		XSAny ep = builder.buildObject(TrustConstants.WST_NS, "OnBehalfOf", TrustConstants.WST_PREFIX);
		
		ep.getUnknownXMLObjects().add(onBehalfOf);
		
		children.add(ep);

		return children;
	}
    
    private XMLObject createTextElement(String element, String content) {
		XSAny ep = builder.buildObject(TrustConstants.WST_NS, element, TrustConstants.WST_PREFIX);
		ep.setTextContent(content);
    	return ep;
    }


	public String getTokenType() {
		return tokenType;
	}
	
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	
	public String getRequestType() {
		return requestType;
	}
	
	public void setRequestType(String requestType) {
		this.requestType = requestType;
	}

	public SecurityTokenReference getOnBehalfOf() {
		return onBehalfOf;
	}
	
	public void setOnBehalfOf(Assertion onBehalfOf) {
		SecurityTokenReference ref = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		ref.setTokenType(tokenType);
		
		KeyIdentifier ki = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		ki.setValueType(TrustConstants.SAMLID);
		ki.setTextContent(onBehalfOf.getID());
		
		ref.setKeyIdentifier(ki);
		setOnBehalfOf(ref);
	}
	
	public void setOnBehalfOf(SecurityTokenReference reference) {
		onBehalfOf = reference;
	}
	
	public String getAppliesTo() {
		return appliesTo;
	}
	
	public void setAppliesTo(String appliesTo) {
		this.appliesTo = appliesTo;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	
	public String getIssuer() {
		return issuer;
	}
}
