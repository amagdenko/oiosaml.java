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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Client interface for retrieving STS tokens via WS-Trust 1.3.
 * 
 * <p>Call {@link #getToken()} to make an STS Issue request.</p>
 * 
 * <p>Instances of this class are not considered thread-safe. They can, however, be reused.</p>
 * 
 * @author Joakim Recht
 *
 */
public class TrustClient extends ClientBase {
	
	private static final Logger log = Logger.getLogger(TrustClient.class);
	
	private String endpoint;
	private final EndpointReference epr;
	private String appliesTo;

	private String issuer;

	private PublicKey stsKey;


	private boolean useReferenceForOnBehalfOf = false;

	private Assertion token;
	
	private String claimsDialect;
	private List<String> claims = new ArrayList<String>();
	
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
	 * <li>oiosaml-trust.bootstrap.base64: Set to false if the bootstrap EPR attribute contains regular XML. Default value is false.</li>
	 * </ul>
	 * 
	 * <p>Furthermore, this constructor assumes that a valid SAML assertion has been placed in {@link UserAssertionHolder} (which should be the case if the OIOSAML SPFilter is configured correctly),
	 * and that the assertion contains an DiscoveryEPR attribute.</p>
	 */
	public TrustClient() {
		this(UserAssertionHolder.get().getAttribute(TrustConstants.DISCOVERY_EPR_ATTRIBUTE), 
				credentialRepository.getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(
				SAMLConfiguration.getSystemConfiguration(), Constants.PROP_CERTIFICATE_LOCATION), 
				SAMLConfiguration.getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD)), null, SAMLConfiguration.getSystemConfiguration().getBoolean(TrustConstants.PROP_BOOTSTRAP_ATTRIBUTE_BASE64, true));
		
		X509Certificate certificate = credentialRepository.getCertificate(SAMLConfiguration.getStringPrefixedWithBRSHome(SAMLConfiguration.getSystemConfiguration(), TrustConstants.PROP_CERTIFICATE_LOCATION),
				SAMLConfiguration.getSystemConfiguration().getString(TrustConstants.PROP_CERTIFICATE_PASSWORD),
				SAMLConfiguration.getSystemConfiguration().getString(TrustConstants.PROP_CERTIFICATE_ALIAS));
		
		stsKey = certificate.getPublicKey();
	}
	
	public TrustClient(UserAttribute eprAttribute, X509Credential credential, PublicKey stsKey, boolean eprIsBase64) {
		super(credential);
		if (eprAttribute != null) {
			log.debug("EPR Attribute: " + eprAttribute);
			if (eprIsBase64) {
				this.epr = (EndpointReference)SAMLUtil.unmarshallElement(new ByteArrayInputStream(eprAttribute.getBase64Value()));
			} else {
				this.epr = (EndpointReference)SAMLUtil.unmarshallElementFromString(eprAttribute.getValue());
			}
		} else {
			this.epr = null;
		}
		this.stsKey = stsKey;
		if (this.epr != null) {
			endpoint = this.epr.getAddress().getValue();
		}
	}

	/**
	 * Create a new token client.
	 * 
	 * @param epr Discovery EPR value. The EPR must contain Metadata/SecurityContext/Assertion, and must have an Address pointing to the STS endpoint.
	 * @param credential Credentials to use for signing the request.
	 * @param stsKey The STS public key used for validating the response.
	 */
	public TrustClient(EndpointReference epr, X509Credential credential, PublicKey stsKey) {
		super(credential);
		this.epr = epr;
		this.stsKey = stsKey;
		
		if (epr != null) {
			endpoint = epr.getAddress().getValue();
		}
	}

	public Assertion getToken() {
		return getToken(null);
	}
	
	/**
	 * Execute a Issue request against the STS.
	 * 
	 * The retrieved token is saved in the client for use if {@link #sendRequest(XMLObject, String, String, PublicKey)} is called.
	 * 
	 * @param dialect The Claims dialect to add to the request. If <code>null</code>, no Claims are added.
	 * @return A DOM element with the returned token.
	 * @throws TrustException If any error occurred.
	 */
	public Assertion getToken(DateTime lifetimeExpire) throws TrustException {
		try {
			String xml = toXMLRequest(lifetimeExpire);
			setRequestXML(xml);
			
			log.debug(xml);
			
			OIOSoapEnvelope env = new OIOSoapEnvelope(soapClient.wsCall(endpoint, null, null, true, xml, "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"));
			setLastResponse(env);
	
			if (!env.verifySignature(stsKey)) {
				throw new TrustException("Response was not signed correctly");
			}
			
			//TODO: Support tokens in security header
			
			log.debug("STS Response: " + env.toXML());
			XMLObject res = env.getBody();
			if (res instanceof Fault) {
				Fault f = (Fault) res;
				throw new TrustException("Unable to retrieve STS token: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(f));
			} else if (res instanceof RequestSecurityTokenResponse) {
				RequestSecurityTokenResponse tokenResponse = (RequestSecurityTokenResponse) res;
				
				return findToken(tokenResponse);
			} else if (res instanceof RequestSecurityTokenResponseCollection){
				RequestSecurityTokenResponse tokenResponse = ((RequestSecurityTokenResponseCollection)res).getRequestSecurityTokenResponses().get(0);
				
				return findToken(tokenResponse);
			} else {
				for (XMLObject object : res.getOrderedChildren()) {
					if (object instanceof RequestedSecurityToken) {
						XMLObject token = ((RequestedSecurityToken)object).getUnknownXMLObject();
						if (!(token instanceof Assertion)) {
							throw new TrustException("Returned token is not a SAML Assertion: " + token);
						} else {
							return validateToken((Assertion) token);
						}
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

	private Assertion findToken(RequestSecurityTokenResponse tokenResponse) {
		RequestedSecurityToken rst = SAMLUtil.getFirstElement(tokenResponse, RequestedSecurityToken.class);
		XMLObject token = rst.getUnknownXMLObject();
		if (!(token instanceof Assertion)) {
			throw new TrustException("Returned token is not a SAML Assertion: " + token);
		} else {
			return validateToken((Assertion) token);
		}
	}

	private Assertion validateToken(Assertion token) {
		OIOAssertion a = new OIOAssertion(token);
		if (!a.verifySignature(stsKey)) {
			log.error("Token is not signed correctly by the STS");
			throw new TrustException("Token assertion does not contain a valid signature");
		}
		this.token = token;
		token.detach();
		return token;
	}

	/**
	 * Get the bootstrap token from the DiscoveryEPR.
	 */
	public OIOAssertion getBootstrap() {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getUnknownXMLObjects(SecurityContext.ELEMENT_NAME));
		return new OIOAssertion((Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(SAMLUtil.marshallObject(token.getAssertion()))));
	}
	
	private String toXMLRequest(DateTime lifetimeExpire) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getUnknownXMLObjects(SecurityContext.ELEMENT_NAME));
		
        OIOIssueRequest req = OIOIssueRequest.buildRequest();
        
        if (issuer != null) {
        	req.setIssuer(issuer);
        }
        if (claimsDialect != null || claims.size() > 0) {
        	req.setClaims(claimsDialect, claims.toArray(new String[0]));
        }
        if (lifetimeExpire != null) {
        	req.setLifetime(lifetimeExpire);
        }
		
		
		req.setAppliesTo(appliesTo);

		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope(soapVersion, signingPolicy);
		env.setAction("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");
		env.setTo(endpoint);
		env.setReplyTo("http://www.w3.org/2005/08/addressing/anonymous");
		env.setBody(req.getXMLObject());
		env.setTimestamp(5);

		if (useReferenceForOnBehalfOf) {
			token.getAssertion().detach();
			req.setOnBehalfOf(token.getAssertion().getID());
			env.addSecurityToken(token.getAssertion());
		} else {
			req.setOnBehalfOf(token.getAssertion());
		}
		
		Element signed = env.sign(getCredential());
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
	 * Configure whether bootstrap tokens should be placed directly in OnBehalfOf or in the Security header using a SecurityTokenReference.
	 * @param useReferenceForOnBehalfOf <code>true</code> to put the token in the security header.
	 */
	public void setUseReferenceForOnBehalfOf(boolean useReferenceForOnBehalfOf) {
		this.useReferenceForOnBehalfOf = useReferenceForOnBehalfOf;
	}

	/**
	 * Get a client for invoking web services using the token retrieved with {@link TrustClient#getToken(String)}.
	 * 
	 * The client will be configured with the same soapclient, soapversion, and credentials as the trustclient. 
	 */
	public ServiceClient getServiceClient() {
		ServiceClient client = new ServiceClient(getCredential());
		client.setSOAPClient(soapClient);
		client.setSoapVersion(soapVersion);
		client.setToken(token);
		
		return client;
	}

	public void setClaimsDialect(String dialect) {
		claimsDialect = dialect;
	}
	
	public void addClaim(String claim) {
		claims.add(claim);
	}
}
