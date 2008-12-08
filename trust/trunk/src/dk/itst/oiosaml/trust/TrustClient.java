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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Detail;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.schema.impl.XSAnyUnmarshaller;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.common.SOAPException;
import dk.itst.oiosaml.configuration.SAMLConfiguration;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.UserAttribute;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.SOAPClient;

/**
 * Client interface for retrieving STS tokens and sending OIOIDWS-based SOAP requests.
 * 
 * <p>Call {@link #getToken()} to make an STS Issue request.</p>
 * 
 * <p>Instances of this class are not considered thread-safe. They can, however, be reused.</p>
 * 
 * @author Joakim Recht
 *
 */
public class TrustClient {
	static {
		TrustBootstrap.bootstrap();
	}
	
	private static final Logger log = Logger.getLogger(TrustClient.class);
	private static final CredentialRepository credentialRepository = new CredentialRepository();
	
	private SOAPClient soapClient = new HttpSOAPClient();
	private String endpoint;
	private final EndpointReference epr;
	private final X509Credential credential;
	private String appliesTo;

	private String issuer;

	private PublicKey stsKey;

	private Assertion token;

	private UserInteraction interact;

	private boolean redirect;
	
	private Map<QName, FaultHandler> faultHandlers = new HashMap<QName, FaultHandler>();

	private boolean signRequests = true;

	private String requestXML;
	private OIOSoapEnvelope lastResponse;

	private String soapVersion = SOAPConstants.SOAP11_NS;
	private SigningPolicy signingPolicy = new SigningPolicy(true);
	private boolean useReferenceForOnBehalfOf = false;
	
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
	 * <p>Furthermore, this constructor assumes that a valid SAML assertion has been placed in {@link UserAssertionHolder} (which should be the case if the OIOSAML SPFilter is configured correctly),
	 * and that the assertion contains an DiscoveryEPR attribute.</p>
	 */
	public TrustClient() {
		this(UserAssertionHolder.get().getAttribute(TrustConstants.DISCOVERY_EPR_ATTRIBUTE), 
				credentialRepository.getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(
				SAMLConfiguration.getSystemConfiguration(), Constants.PROP_CERTIFICATE_LOCATION), 
				SAMLConfiguration.getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD)), null);
		
		X509Certificate certificate = credentialRepository.getCertificate(SAMLConfiguration.getStringPrefixedWithBRSHome(SAMLConfiguration.getSystemConfiguration(), TrustConstants.PROP_CERTIFICATE_LOCATION),
				SAMLConfiguration.getSystemConfiguration().getString(TrustConstants.PROP_CERTIFICATE_PASSWORD),
				SAMLConfiguration.getSystemConfiguration().getString(TrustConstants.PROP_CERTIFICATE_ALIAS));
		
		stsKey = certificate.getPublicKey();
	}
	
	public TrustClient(UserAttribute eprAttribute, X509Credential credential, PublicKey stsKey) {
		if (eprAttribute != null) {
			this.epr = (EndpointReference)SAMLUtil.unmarshallElement(new ByteArrayInputStream(eprAttribute.getBase64Value()));
		} else {
			this.epr = null;
		}
		this.credential = credential;
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
		this.epr = epr;
		this.credential = credential;
		this.stsKey = stsKey;
		
		if (epr != null) {
			endpoint = epr.getAddress().getValue();
		}
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
	public Element getToken(String dialect) throws TrustException {
		try {
			String xml = toXMLRequest(dialect);
			this.requestXML = xml;
			
			log.debug(xml);
			
			OIOSoapEnvelope env = new OIOSoapEnvelope(soapClient.wsCall(endpoint, null, null, true, xml, "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"));
			lastResponse = env;
	
			//TODO: finish validation when STS supports signatures in security header
//			env.verifySignature(stsKey);
			
			//TODO: Support tokens in security header
			
			log.debug("STS Response: " + env.toXML());
			XMLObject res = env.getBody();
			if (res instanceof Fault) {
				Fault f = (Fault) res;
				throw new TrustException("Unable to retrieve STS token: " + SAMLUtil.getSAMLObjectAsPrettyPrintXML(f));
			} else if (res instanceof RequestSecurityTokenResponse) {
				RequestSecurityTokenResponse tokenResponse = (RequestSecurityTokenResponse) res;
				
				return validateToken(SAMLUtil.getFirstElement(tokenResponse.getRequestedSecurityToken(), Assertion.class));
			} else if (res instanceof RequestSecurityTokenResponseCollection){
				RequestSecurityTokenResponse tokenResponse = ((RequestSecurityTokenResponseCollection)res).getRequestSecurityTokenResponses().get(0);
				
				return validateToken(SAMLUtil.getFirstElement(tokenResponse.getRequestedSecurityToken(), Assertion.class));
			} else {
				for (XMLObject object : res.getOrderedChildren()) {
					if (object.getElementQName().equals(RequestedSecurityToken.ELEMENT_NAME)) {
						return validateToken(SAMLUtil.getFirstElement((RequestedSecurityToken)object, Assertion.class));
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

	private Element validateToken(Assertion token) {
		OIOAssertion a = new OIOAssertion(token);
		if (!a.verifySignature(stsKey)) {
			log.error("Token is not signed correctly by the STS");
			throw new TrustException("Token assertion does not contain a valid signature");
		}
		setToken(token);
		return token.getDOM();
	}

	/**
	 * Get the bootstrap token from the DiscoveryEPR.
	 */
	public OIOAssertion getBootstrap() {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getUnknownXMLObjects(SecurityContext.ELEMENT_NAME));
		return new OIOAssertion((Assertion) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(SAMLUtil.marshallObject(token.getAssertion()))));
	}
	
	private String toXMLRequest(String dialect) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Token token = getToken("urn:liberty:security:tokenusage:2006-08:SecurityToken", epr.getMetadata().getUnknownXMLObjects(SecurityContext.ELEMENT_NAME));
		
        OIOIssueRequest req = OIOIssueRequest.buildRequest();
        
        if (issuer != null) {
        	req.setIssuer(issuer);
        }
        if (dialect != null) {
        	req.setClaims(dialect);
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
	
	/**
	 * Execute a SOAP request.
	 * 
	 * <p>A SOAP header is added automatically to the request containing the client's security token.</p>
	 * <p>If {@link #getToken()} has been called, the retrieved token is added to the request automatically.</p>
	 * 
	 * <p>SOAP Faults can be handled by adding {@link FaultHandler}s to the client.</p>
	 * 
	 * @see FaultHandler Handle SOAP Faults.
	 * @param body The body of the request.
	 * @param location Location to send request to.
	 * @param action SOAP Action to invoke.
	 * @param verificationKey Key to use for signature verification on the response. If <code>null</code>, the signature is not checked. If the signature is not valid, a {@link TrustException} is thrown.
	 * @param resultHandler When the request has been completed, the response will be sent to this callback. The handler can be <code>null</code>, in which case the response is ignored.
	 * @throws InvocationTargetException Thrown when an exception is thrown in a handler.
	 * @throws TrustException If an unhandled SOAP Fault occurs, or if a transport error occurs.
	 */
	public void sendRequest(XMLObject body, String location, String action, PublicKey verificationKey, ResultHandler<XMLObject> resultHandler) throws InvocationTargetException {
		if (log.isDebugEnabled()) log.debug("Invoking action " + action + " at service " + location);
		
		body.detach();
		OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope(soapVersion, signingPolicy);
		env.setBody(body);
		env.setAction(action);
		env.setTo(location);
		env.setReplyTo("http://www.w3.org/2005/08/addressing/anonymous");
		env.setTimestamp(5);
		env.addSecurityTokenReference(token);
		
		if (interact != null) {
			if (log.isDebugEnabled()) log.debug("UserInteract set: " + interact + ", redirect: " + redirect);
			env.setUserInteraction(interact, redirect);
		}
		
		try {
			Element request;
			if (signRequests) {
				request = env.sign(credential);
			} else {
				env.getHeaderElement(Security.class).setMustUnderstand(new XSBooleanValue(false, true));
				request = SAMLUtil.marshallObject(env.getXMLObject());
			}
			
			requestXML = XMLHelper.nodeToString(request);
			if (log.isDebugEnabled()) log.debug("Signed request: " + requestXML);
			
			OIOSoapEnvelope res = new OIOSoapEnvelope(soapClient.wsCall(location, null, null, true, requestXML, action));
			lastResponse = res;
			if (!res.relatesTo(env.getMessageID())) {
				log.error("Respose is not reply to " + env.getMessageID());
				throw new TrustException("Respose is not reply to " + env.getMessageID());
			}
			if (verificationKey != null && signRequests) {
				log.debug("Verifying signature on response");
				if (!res.verifySignature(verificationKey)) {
					throw new TrustException("Signature on response is not valid. Response contains signature: " + res.isSigned());
				}
			}
			
			if (resultHandler != null) {
				try {
					resultHandler.handleResult(res.getBody());
				} catch (Exception e) {
					throw new InvocationTargetException(e);
				}
			}
		} catch (SOAPException e) {
			Fault fault = e.getFault();
			if (fault != null && fault.getDetail() != null) {
				Detail detail = fault.getDetail();
				
				QName code = null;
				if (fault.getCode() != null) code = fault.getCode().getValue();
				
				String message = null;
				if (fault.getMessage() != null) message = fault.getMessage().getValue();
				
				if (log.isDebugEnabled()) log.debug("Finding fault handler for " + detail.getUnknownXMLObjects());
				for (XMLObject el : detail.getUnknownXMLObjects()) {
					FaultHandler handler = faultHandlers.get(el.getElementQName());
					if (handler != null) {
						if (log.isDebugEnabled()) log.debug("Found fault handler for " + el.getElementQName() + ": " + handler);
						try {
							handler.handleFault(code, message, el);
						} catch (Exception ex) {
							throw new InvocationTargetException(ex);
						}
						return;
					}
				}
				throw new TrustException("Unhandled SOAP Fault", e);
			} else {
				if (log.isDebugEnabled()) log.debug("No handler for fault " + e);
				throw new TrustException(e);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new TrustException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new TrustException(e);
		} catch (MarshalException e) {
			throw new TrustException(e);
		} catch (XMLSignatureException e) {
			throw new TrustException(e);
		} catch (IOException e) {
			throw new TrustException(e);
		}
	}

	public void sendRequest(Element body, String location, String action, PublicKey verificationKey, final ResultHandler<Element> resultHandler) throws InvocationTargetException {
		try {
			XMLObject any = new XSAnyUnmarshaller().unmarshall(body);
			
			sendRequest(any, location, action, verificationKey, new ResultHandler<XMLObject>() {
				public void handleResult(XMLObject result) throws Exception {
					if (resultHandler != null) {
						resultHandler.handleResult(SAMLUtil.marshallObject(result));
					}
				}
			});
		} catch (UnmarshallingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Send a request using JAXB types.
	 * @param <T> The response type. No type checking is performed, so if this type is not correct, a {@link ClassCastException} will occur.
	 * @param body The request body. Must be a JAXB-mapped object.
	 * @param context A JAXB context which recognized the body object.
	 * @param location Location of the service. 
	 * @param action SOAP Action to invoke.
	 * @param verificationKey Key to use for signature validation.
	 * @param resultHandler Handler for the result.
	 */
	public <T> void sendRequest(Object body, final JAXBContext context, String location, String action, PublicKey verificationKey, final ResultHandler<T> resultHandler) {
		try {
			Marshaller marshaller = context.createMarshaller();
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().newDocument();

			Object factory = Class.forName(body.getClass().getPackage().getName() + ".ObjectFactory").newInstance();
			String name = body.getClass().getName();
			Method m = factory.getClass().getDeclaredMethod("create" + name.substring(name.lastIndexOf('.') + 1), body.getClass());
			Object jaxbElement = m.invoke(factory, body);
			
			marshaller.marshal(jaxbElement, doc);
			
			XMLObject any = new XSAnyUnmarshaller().unmarshall(doc.getDocumentElement());
			
			sendRequest(any, location, action, verificationKey, new ResultHandler<XMLObject>() {
				@SuppressWarnings("unchecked")
				public void handleResult(XMLObject result) throws Exception {
					if (resultHandler != null) {
						Unmarshaller unmarshaller = context.createUnmarshaller();
						Object body = unmarshaller.unmarshal(SAMLUtil.marshallObject(result));
						if (body instanceof JAXBElement) {
							resultHandler.handleResult((T) ((JAXBElement<T>)body).getValue());
						} else {
							resultHandler.handleResult((T) body);
						}
					}
				}
			});
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
	}
	
	/**
	 * Set the client to use when executing the request.
	 */
	public void setSOAPClient(SOAPClient client) {
		this.soapClient = client;
	}

	/**
	 * Set the UserInteract value for requests.
	 */
	public void setUserInteraction(UserInteraction interact, boolean redirect) {
		this.interact = interact;
		this.redirect = redirect;
	}
	
	/**
	 * Add a new fault handler.
	 * @see #addFaultHandler(QName, FaultHandler)
	 * @param namespace
	 * @param localName
	 * @param handler
	 */
	public void addFaultHander(String namespace, String localName, FaultHandler handler) {
		addFaultHandler(new QName(namespace, localName), handler);
	}
	
	/**
	 * Add a fault handler for a specific soap fault type.
	 * 
	 * The registered type is matched against the types in Fault/Detail. If a matching QName element is found, the fault handler is invoked.
	 * Only one handler is invoked for a Fault - the first matching element.
	 * 
	 * @param element Detail element to match.
	 */
	public void addFaultHandler(QName element, FaultHandler handler) {
		faultHandlers.put(element, handler);
	}
	
	/**
	 * Configure  whether ws requests should be signed or not. Token requests are always signed.
	 * 
	 * Default is <code>true</code>.
	 */
	public void signRequests(boolean sign) {
		this.signRequests = sign;
		
	}
	
	/**
	 * Get the xml sent in the last webservice call, either from {@link #getToken(String)} or from {@link #sendRequest(Element, String, String, PublicKey, ResultHandler)}.
	 */
	public String getLastRequestXML() {
		return requestXML;
	}
	
	/**
	 * Set the SOAP version to use.
	 * @param soapVersion Namespace of the soap version to use. The client defaults to soap 1.1.
	 */
	public void setSoapVersion(String soapVersion) {
		this.soapVersion = soapVersion;
	}
	
	/**
	 * Set the signing policy for ws requests.
	 */
	public void setSigningPolicy(SigningPolicy signingPolicy) {
		this.signingPolicy = signingPolicy;
	}

	/**
	 * Configure whether bootstrap tokens should be placed directly in OnBehalfOf or in the Security header using a SecurityTokenReference.
	 * @param useReferenceForOnBehalfOf <code>true</code> to put the token in the security header.
	 */
	public void setUseReferenceForOnBehalfOf(boolean useReferenceForOnBehalfOf) {
		this.useReferenceForOnBehalfOf = useReferenceForOnBehalfOf;
	}

	public OIOSoapEnvelope getLastResponse() {
		return lastResponse;
	}
}
