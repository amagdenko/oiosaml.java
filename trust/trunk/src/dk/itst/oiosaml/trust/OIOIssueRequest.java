/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Trust Client.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
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

/**
 * Representation of a OIO WS-Trust Issue request.
 * 
 * @author recht
 *
 */
public class OIOIssueRequest {

	private final RequestSecurityToken request;

	public OIOIssueRequest(RequestSecurityToken request) {
		this.request = request;
	}
	
	/**
	 * Create a new request.
	 * 
	 * This builds a new request and sets the token type to saml2.
	 */
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

	/**
	 * Set the assertion id of the attached assertion. The assertion must be placed in the Security header as a SecurityTokenReference.
	 */
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
