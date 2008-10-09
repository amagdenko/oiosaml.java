package dk.itst.oiosaml.trust;

import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.OnBehalfOf;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestType;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;

public class OIOIssueRequest {

	private final RequestSecurityToken request;

	public OIOIssueRequest(RequestSecurityToken request) {
		this.request = request;
	}
	
	public static OIOIssueRequest buildRequest() {
		RequestSecurityToken req = SAMLUtil.buildXMLObject(RequestSecurityToken.class);
		RequestType type = SAMLUtil.buildXMLObject(RequestType.class);
		type.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");
		req.setRequestType(type);

		TokenType tokenType = SAMLUtil.buildXMLObject(TokenType.class);
		tokenType.setValue(TrustConstants.TOKEN_TYPE_SAML_20);
		req.setTokenType(tokenType);
		
		return new OIOIssueRequest(req);
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
