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
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.trust;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.Created;
import org.opensaml.ws.wssecurity.Expires;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.ws.wstrust.Issuer;
import org.opensaml.ws.wstrust.OnBehalfOf;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.xml.AttributeExtensibleXMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.BRSConfiguration;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

public class TokenClient {
	private static final Logger log = Logger.getLogger(TokenClient.class);
	
	private String endpoint;
	private final EndpointReference epr;
	private final X509Credential credential;
	private String appliesTo;
	
	public TokenClient() {
		this((EndpointReference) SAMLUtil.unmarshallElementFromString(UserAssertionHolder.get().getAttribute("DiscoveryEPR").getValue()), 
				Utils.getCredential(BRSConfiguration.getStringPrefixedWithBRSHome(
				BRSConfiguration.getSystemConfiguration(), Constants.PROP_CERTIFICATE_LOCATION), 
				BRSConfiguration.getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD)));
	}
	
	public TokenClient(EndpointReference epr, X509Credential credential) {
		this.epr = epr;
		this.credential = credential;
		
		if (epr != null) {
			endpoint = epr.getAddress().getValue();
		}

		TrustBootstrap.bootstrap();
	}

	public Element request() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		String xml = toXMLRequest();
		
		log.debug(xml);
		
		HttpSOAPClient client = new HttpSOAPClient();
		try {
			XMLObject res = client.wsCall(new LogUtil(getClass(), ""), endpoint, null, null, true, xml);
			
			log.debug("STS Response: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(res));
			
			if (res instanceof Fault) {
				Fault f = (Fault) res;
				throw new TrustException("Unable to retrieve STS token: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(f));
			} else {
				RequestSecurityTokenResponseCollection c = (RequestSecurityTokenResponseCollection) res;
				RequestSecurityTokenResponse tokenResponse = c.getRequestSecurityTokenResponses().get(0);
				
				return tokenResponse.getRequestedSecurityToken().getUnknownXMLObjects(Assertion.DEFAULT_ELEMENT_NAME).get(0).getDOM();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public String toXMLRequest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getUnknownXMLObjects(SecurityContext.ELEMENT_NAME));
		
        OIOIssueRequest req = OIOIssueRequest.buildRequest();
        req.setIssuer("urn:issuer");
        
		token.getAssertion().detach();
		
		req.setOnBehalfOf(token.getAssertion().getID());
		
		req.setAppliesTo(appliesTo);

		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope();
		env.setBody(req);
		env.setAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
		env.setTimestamp(5);
		env.addSecurityToken(token.getAssertion());
		
		Element signed = env.sign(credential);
		return XMLHelper.nodeToString(signed);
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}
	
	public void setAppliesTo(String appliesTo) {
		this.appliesTo = appliesTo;
	}

	private Token getToken(String usage, List<XMLObject> list) {
		for (Iterator<XMLObject> iterator = list.iterator(); iterator.hasNext();) {
			SecurityContext ctx = (SecurityContext) iterator.next();
			for (Token t : ctx.getTokens()) {
				if (usage.equals(t.getUsage())) {
					return t;
				}
			}
		}
		throw new IllegalArgumentException("No token with usage type " + usage);
	}
	
}
