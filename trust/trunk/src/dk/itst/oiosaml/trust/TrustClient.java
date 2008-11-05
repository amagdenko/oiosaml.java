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
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.error.ValidationException;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.Utils;

/**
 * Client interface for retrieving STS tokens.
 * 
 * Call {@link #getToken()} to make an STS Issue request.
 * 
 * @author Joakim Recht
 *
 */
public class TrustClient {
	private static final Logger log = Logger.getLogger(TrustClient.class);
	
	private String endpoint;
	private final EndpointReference epr;
	private final X509Credential credential;
	private String appliesTo;

	private String issuer;

	private PublicKey stsKey;

	private Assertion token;

	/**
	 * Create a new client using default settings.
	 * 
	 * <p>The default settings are read from the OIOSAML configuration. The following properties are used:</p>
	 * <ul>
	 * <li>oiosaml-sp.certificate.location: SP keystore location</li>
	 * <li>oiosaml-sp.certificate.password: SP keystore password</li>
	 * <li>oiosaml-trust.certificate.location: Keystore containing STS certificate</li>
	 * <li>oiosaml-trust.certificate.password: Password for the sts keystore</li>
	 * <li>oiosaml-trust.certificate.alias: Certificate alias for the sts certificate</li>
	 * </ul>
	 * 
	 * Furthermore, this constructor assumes that a valid SAML assertion has been placed in {@link UserAssertionHolder},
	 * and that the assertion contains an DiscoveryEPR attribute.
	 */
	public TrustClient() {
		this((EndpointReference) SAMLUtil.unmarshallElementFromString(UserAssertionHolder.get().getAttribute("DiscoveryEPR").getValue()), 
				Utils.getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(
				SAMLConfiguration.getSystemConfiguration(), Constants.PROP_CERTIFICATE_LOCATION), 
				SAMLConfiguration.getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD)), null);
		
		X509Certificate certificate = Utils.getCertificate(SAMLConfiguration.getStringPrefixedWithBRSHome(SAMLConfiguration.getSystemConfiguration(), TrustConstants.PROP_CERTIFICATE_LOCATION),
				SAMLConfiguration.getSystemConfiguration().getString(TrustConstants.PROP_CERTIFICATE_PASSWORD),
				SAMLConfiguration.getSystemConfiguration().getString(TrustConstants.PROP_CERTIFICATE_ALIAS));
		
		stsKey = certificate.getPublicKey();
	}

	/**
	 * Create a new token client.
	 * 
	 * @param epr Discovery EPR value. The EPR must contain Metadata/SecurityContext/Assertion, and must have an Address pointing to the STS endpoint.
	 * @param credential Credentials to use for signing the request.
	 * @param stsKey The STS public key used for validating the response.
	 */
	public TrustClient(EndpointReference epr, X509Credential credential, PublicKey stsKey) {
		this.epr = epr;
		this.credential = credential;
		this.stsKey = stsKey;
		
		if (epr != null) {
			endpoint = epr.getAddress().getValue();
		}

		TrustBootstrap.bootstrap();
	}

	/**
	 * Execute a Issue request against the STS.
	 * 
	 * @return A DOM element with the returned token.
	 * @throws TrustException If any error occurred.
	 */
	public Element getToken() throws TrustException {
		try {
			String xml = toXMLRequest();
			
			log.debug(xml);
			
			HttpSOAPClient client = new HttpSOAPClient();
			
			Envelope env = client.wsCall(endpoint, null, null, true, xml, "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
	
			//TODO: finish validation when STS supports signatures in security header
//			validateSignature(env);

			//TODO: Support tokens in security header
			
			log.debug("STS Response: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(env));
			XMLObject res = env.getBody().getUnknownXMLObjects().get(0);
			if (res instanceof Fault) {
				Fault f = (Fault) res;
				throw new TrustException("Unable to retrieve STS token: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(f));
			} else if (res instanceof RequestSecurityTokenResponse) {
				RequestSecurityTokenResponse tokenResponse = (RequestSecurityTokenResponse) res;
				
				Assertion dom = (Assertion) tokenResponse.getRequestedSecurityToken().getUnknownXMLObjects(Assertion.DEFAULT_ELEMENT_NAME).get(0);
				setToken(dom);
				return dom.getDOM();
			} else {
				for (XMLObject object : res.getOrderedChildren()) {
					if (object.getElementQName().equals(RequestedSecurityToken.ELEMENT_NAME)) {
						Assertion dom = (Assertion) ((RequestedSecurityToken)object).getUnknownXMLObjects(Assertion.DEFAULT_ELEMENT_NAME).get(0);
						setToken(dom);
						return dom.getDOM();
					}
				}
				throw new TrustException("Got a " + res.getElementQName() + ", expected " + RequestSecurityTokenResponse.ELEMENT_NAME);
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new TrustException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new TrustException(e);
		} catch (MarshalException e) {
			throw new TrustException(e);
		} catch (XMLSignatureException e) {
			throw new TrustException(e);
		}
	}

	private void validateSignature(Envelope env) {
		Security sec = (Security) env.getHeader().getUnknownXMLObjects(Security.ELEMENT_NAME).get(0);
		
		Signature signature = (Signature) sec.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME).get(0);
		BasicX509Credential credential = new BasicX509Credential();
		credential.setPublicKey(stsKey);
		SignatureValidator validator = new SignatureValidator(credential);
		try {
			validator.validate(signature);
		} catch (org.opensaml.xml.validation.ValidationException e) {
			throw new ValidationException("STS signature is not valid: " + e.getMessage());
		}
	}
	
	
	public String toXMLRequest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getUnknownXMLObjects(SecurityContext.ELEMENT_NAME));
		
        OIOIssueRequest req = OIOIssueRequest.buildRequest();
        
        if (issuer != null) {
        	req.setIssuer(issuer);
        }
        
		token.getAssertion().detach();
		
		req.setOnBehalfOf(token.getAssertion().getID());
		
		req.setAppliesTo(appliesTo);

		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope();
		env.setBody(req.getXMLObject());
		env.setAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
		env.setTo(endpoint);
		env.setReplyTo("http://www.w3.org/2005/08/addressing/anonymous");
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
	
	public void setIssuer(String issuer) {
		this.issuer = issuer;
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
	
	
	/**
	 * Set the security token used for webservice requests.
	 * @param token
	 */
	public void setToken(Assertion token) {
		this.token = token;
	}
	
	public XMLObject sendRequest(XMLObject body, String location, String action) {
		body.detach();
		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope();
		env.setBody(body);
		env.setAction(action);
		env.setTo(endpoint);
		env.setReplyTo("http://www.w3.org/2005/08/addressing/anonymous");
		env.setTimestamp(5);
		env.addSecurityTokenReference(token);
		
		try {
			Element signed = env.sign(credential);
			
			log.debug("Signed request: " + XMLHelper.nodeToString(signed));
			
			HttpSOAPClient client = new HttpSOAPClient();
			
			Envelope res = client.wsCall(location, null, null, true, XMLHelper.nodeToString(signed), action);
			
			return res.getBody().getUnknownXMLObjects().get(0);
		} catch (Exception e) {
			throw new TrustException(e);
		}
	}
}
