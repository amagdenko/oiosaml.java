package dk.itst.oiosaml.trust;

import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.xml.security.x509.X509Credential;

import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.service.util.HttpSOAPClient;
import dk.itst.oiosaml.sp.service.util.SOAPClient;

public abstract class ClientBase {
	static {
		TrustBootstrap.bootstrap();
	}
	
	protected static final CredentialRepository credentialRepository = new CredentialRepository();

	protected SOAPClient soapClient = new HttpSOAPClient();
	private final X509Credential credential;


	protected String soapVersion = SOAPConstants.SOAP11_NS;
	protected SigningPolicy signingPolicy = new SigningPolicy(true);
	
	private String requestXML;
	private OIOSoapEnvelope lastResponse;

	public ClientBase(X509Credential credential) {
		this.credential = credential;
	}

	protected void setRequestXML(String xml) {
		requestXML = xml;
	}
	
	protected void setLastResponse(OIOSoapEnvelope env) {
		lastResponse = env;
	}

	public String getLastRequestXML() {
		return requestXML;
	}

	/**
	 * Set the client to use when executing the request.
	 */
	public void setSOAPClient(SOAPClient client) {
		this.soapClient = client;
	}

	/**
	 * Set the SOAP version to use.
	 * @param soapVersion Namespace of the soap version to use. The client defaults to soap 1.1.
	 */
	public void setSoapVersion(String soapVersion) {
		this.soapVersion = soapVersion;
	}
	
	public OIOSoapEnvelope getLastResponse() {
		return lastResponse;
	}
	
	/**
	 * Set the signing policy for ws requests.
	 */
	public void setSigningPolicy(SigningPolicy signingPolicy) {
		this.signingPolicy = signingPolicy;
	}

	protected X509Credential getCredential() {
		return credential;
	}
}
