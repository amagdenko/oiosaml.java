package dk.itst.oiosaml.trust;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;

public class RequestedSecurityToken extends TrustObject {

    public static final String DEFAULT_ELEMENT_LOCAL_NAME = "RequestedSecurityToken"; 
    public static final QName DEFAULT_ELEMENT_NAME = XMLHelper.constructQName(TrustConstants.WST_NS, DEFAULT_ELEMENT_LOCAL_NAME, TrustConstants.WST_PREFIX);
    
	private List<Assertion> assertions = new ArrayList<Assertion>();
	
	protected RequestedSecurityToken(String namespaceURI, String elementLocalName, String namespacePrefix) 
	{
		super(namespaceURI, elementLocalName, namespacePrefix);
	}
	
	
	public List<Assertion> getAssertions() {
		return assertions;
	}
	
	@Override
	protected List<XMLObject> buildOrderedChildren() {
		List<XMLObject> res = new ArrayList<XMLObject>();
		res.addAll(assertions);
		return res;
	}
}
