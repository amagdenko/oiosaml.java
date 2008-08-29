package dk.itst.oiosaml.trust;

import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.OnBehalfOf;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;

public class OIOIssueRequest {

	private final RequestSecurityToken request;

	public OIOIssueRequest(RequestSecurityToken request) {
		this.request = request;
	}
	
	public static OIOIssueRequest buildRequest() {
		return new OIOIssueRequest(SAMLUtil.buildXMLObject(RequestSecurityToken.class));
	}
	
	public void setIssuer(String issuer) {
		Issuer i = SAMLUtil.buildXMLObject(Issuer.class);
		Address issuerAddress = SAMLUtil.buildXMLObject(Address.class);
		issuerAddress.setValue(issuer);
		i.setAddress(issuerAddress);
		request.setIssuer(i);
	}
	
	public void setAppliesTo(String appliesTo) {
		AppliesTo a = SAMLUtil.buildXMLObject(AppliesTo.class);
		EndpointReference ref = SAMLUtil.buildXMLObject(EndpointReference.class);
		Address appliesToAddress = SAMLUtil.buildXMLObject(Address.class);
		appliesToAddress.setValue(appliesTo);
		ref.setAddress(appliesToAddress);
		a.getUnknownXMLObjects().add(ref);
		request.setAppliesTo(a);
	}
	
	public void setOnBehalfOf(String assertionId) {
		OnBehalfOf onBehalfOf = SAMLUtil.buildXMLObject(OnBehalfOf.class);
		SecurityTokenReference oref = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		oref.setTokenType(TrustConstants.TOKEN_TYPE_SAML_20);
		
		KeyIdentifier ki = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		ki.setValueType(TrustConstants.SAMLID);
		ki.setValue(assertionId);
		oref.setKeyIdentifier(ki);

		onBehalfOf.setSecurityTokenReference(oref);
		request.setOnBehalfOf(onBehalfOf);
	}
	
	public XMLObject getXMLObject() {
		return request;
	}
}
