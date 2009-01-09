package dk.itst.oiosaml.trust;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HashMap;
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
import org.opensaml.ws.wssecurity.Security;
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
import dk.itst.oiosaml.sp.service.util.Constants;

/**
 * Client interface for invoking identity based webservices according to the Liberty Basic SOAP Profile.
 * 
 * @author Joakim Recht
 *
 */
public class ServiceClient extends ClientBase {
	private static final Logger log = Logger.getLogger(ServiceClient.class);
	
	private Map<QName, FaultHandler> faultHandlers = new HashMap<QName, FaultHandler>();

	private UserInteraction interact;

	private boolean redirect;
	private Assertion token;
	private boolean endorsingToken;
	private boolean protectTokens = true;
	private boolean signRequests = true;

	/**
	 * Create a new service client using the default OIOSAML credentials.
	 * 
	 * This requires OIOSAML.java to be configured, and will use the credentials specified in oiosaml-sp.properties.
	 */
	public ServiceClient() {
		this(credentialRepository.getCredential(SAMLConfiguration.getStringPrefixedWithBRSHome(
				SAMLConfiguration.getSystemConfiguration(), Constants.PROP_CERTIFICATE_LOCATION), 
				SAMLConfiguration.getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD)));
	}

	public ServiceClient(X509Credential credential) {
		super(credential);
	}

	/**
	 * Set the security token used for webservice requests.
	 * @param token
	 */
	public void setToken(Assertion token) {
		this.token = token;
	}
	
	public void setUseEndorsing(boolean endorsingToken) {
		this.endorsingToken = endorsingToken;
		
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
		if (endorsingToken) {
			env.addEndorsingToken(token, protectTokens);
		} else {
			env.addSecurityTokenReference(token, protectTokens);
		}
		
		if (interact != null) {
			if (log.isDebugEnabled()) log.debug("UserInteract set: " + interact + ", redirect: " + redirect);
			env.setUserInteraction(interact, redirect);
		}
		
		try {
			Element request;
			if (signRequests) {
				request = env.sign(getCredential());
			} else {
				env.getHeaderElement(Security.class).setMustUnderstand(new XSBooleanValue(false, true));
				request = SAMLUtil.marshallObject(env.getXMLObject());
			}
			
			setRequestXML(XMLHelper.nodeToString(request));
			if (log.isDebugEnabled()) log.debug("Signed request: " + getLastRequestXML());
			
			OIOSoapEnvelope res = new OIOSoapEnvelope(soapClient.wsCall(location, null, null, true, getLastRequestXML(), action));
			setLastResponse(res);
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
	 * Set whether to protect security tokens with the message signature or not.
	 * 
	 * @param protectTokens Set token protection. Defaults to <code>true</code>.
	 */
	public void setProtectTokens(boolean protectTokens) {
		this.protectTokens = protectTokens;
	}

}
