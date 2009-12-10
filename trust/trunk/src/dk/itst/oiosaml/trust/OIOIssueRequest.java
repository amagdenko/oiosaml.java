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

import org.joda.time.DateTime;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.Expires;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wstrust.Claims;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.Lifetime;
import org.opensaml.ws.wstrust.OnBehalfOf;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestType;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.liberty.ClaimType;

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
		req.getUnknownXMLObjects().add(type);

		TokenType tokenType = SAMLUtil.buildXMLObject(TokenType.class);
		tokenType.setValue(TrustConstants.TOKEN_TYPE_SAML_20);
		req.getUnknownXMLObjects().add(tokenType);
		
		return new OIOIssueRequest(req);
	}
	
	public void setIssuer(String issuer) {
		Issuer i = SAMLUtil.buildXMLObject(Issuer.class);
		Address issuerAddress = SAMLUtil.buildXMLObject(Address.class);
		issuerAddress.setValue(issuer);
		i.setAddress(issuerAddress);
		replace(i);
	}
	
	private void replace(XMLObject obj) {
		XMLObject old = SAMLUtil.getFirstElement(request, obj.getClass());
		if (old != null) {
			request.getUnknownXMLObjects().remove(old);
		}
		request.getUnknownXMLObjects().add(obj);
	}
	
	public void setAppliesTo(String appliesTo) {
		AppliesTo a = SAMLUtil.buildXMLObject(AppliesTo.class);
		EndpointReference ref = SAMLUtil.buildXMLObject(EndpointReference.class);
		Address appliesToAddress = SAMLUtil.buildXMLObject(Address.class);
		appliesToAddress.setValue(appliesTo);
		ref.setAddress(appliesToAddress);
		a.getUnknownXMLObjects().add(ref);
		replace(a);
	}

	/**
	 * Set the assertion id of the attached assertion. The assertion must be placed in the Security header as a SecurityTokenReference.
	 */
	public void setOnBehalfOf(String assertionId) {
		OnBehalfOf onBehalfOf = SAMLUtil.buildXMLObject(OnBehalfOf.class);
		SecurityTokenReference oref = SAMLUtil.buildXMLObject(SecurityTokenReference.class);
		oref.getUnknownAttributes().put(TrustConstants.TOKEN_TYPE, TrustConstants.TOKEN_TYPE_SAML_20);
		
		KeyIdentifier ki = SAMLUtil.buildXMLObject(KeyIdentifier.class);
		ki.setValueType(TrustConstants.SAMLID);
		ki.setValue(assertionId);
		oref.getUnknownXMLObjects().add(ki);

//		onBehalfOf.setSecurityTokenReference(oref);
		onBehalfOf.setUnknownXMLObject(oref);
		replace(onBehalfOf);
	}
	
	/**
	 * Set the onbehalfof value. This adds the input structure directly to OnBehalfOf.
	 */
	public void setOnBehalfOf(XMLObject obj) {
		obj.detach();
		OnBehalfOf onBehalfOf = SAMLUtil.buildXMLObject(OnBehalfOf.class);
		onBehalfOf.setUnknownXMLObject(obj);
		replace(onBehalfOf);
	}

	/**
	 * Add claims to the request.
	 * 
	 * @param dialect Claims dialect.
	 * @param claimObjects The contents of the Claims element. Any objects will do.
	 */
	public void setClaims(String dialect, XMLObject ... claimObjects) {
		Claims claims = SAMLUtil.buildXMLObject(Claims.class);
		claims.setDialect(dialect);
		
		for (XMLObject co : claimObjects) {
			claims.getUnknownXMLObjects().add(co);
		}
		replace(claims);
	}
	
	/**
	 * Add Identity claims to the request.
	 * 
	 * @param dialect The dialect to use. Can be <code>null</code>.
	 * @param claims The list of claims to include. These are included as ic:ClaimType elements with an Uri attribute.
	 */
	public void setClaims(String dialect, String ... claims) {
		Claims c = SAMLUtil.buildXMLObject(Claims.class);
		c.setDialect(dialect);
		
		for (String claim : claims) {
			ClaimType ct = SAMLUtil.buildXMLObject(ClaimType.class);
			ct.setUri(claim);
			c.getUnknownXMLObjects().add(ct);
		}
		replace(c);
	}
	
	public void setLifetime(DateTime expire) {
		Lifetime lifetime = SAMLUtil.buildXMLObject(Lifetime.class);
		Expires expires = SAMLUtil.buildXMLObject(Expires.class);
		expires.setDateTime(expire);
		lifetime.setExpires(expires);

		replace(lifetime);
	}
	
	public XMLObject getXMLObject() {
		return request;
	}
}
