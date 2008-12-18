package dk.itst.saml.poc.provider;

import javax.annotation.Resource;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.ws.Endpoint;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.XMLObject;

import com.sun.xml.wss.SubjectAccessor;
import com.sun.xml.wss.XWSSecurityException;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.BasicAssertionValidator;
import dk.itst.oiosaml.sp.model.validation.ValidationException;
import dk.itst.saml.poc.idws.Framework;
import dk.itst.saml.poc.idws.FrameworkMismatchFault;
import dk.itst.saml.poc.idws.RequestToInteractFault;
import dk.itst.saml.poc.idws.UserInteraction;

@WebService
@SOAPBinding(style=SOAPBinding.Style.DOCUMENT)
public class Provider {
	private static final Logger log = Logger.getLogger(Provider.class);
	
	@Resource
	private WebServiceContext context;

	@WebMethod(action="http://provider.poc.saml.itst.dk/Provider/echoRequest")
	public @WebResult(name="output", targetNamespace="http://provider.poc.saml.itst.dk/") Structure echo(
			@WebParam(name="Framework", header=true, targetNamespace="urn:liberty:sb:2006-08") Framework framework, 
			@WebParam(name="input", targetNamespace="http://provider.poc.saml.itst.dk/") Structure input) {
		try {
			FrameworkMismatchFault.throwIfNecessary(framework, context.getMessageContext());
			
			Subject subject = SubjectAccessor.getRequesterSubject(context);
			log.info("Credentials: " + subject.getPublicCredentials());
			
			OIOAssertion assertion = new OIOAssertion(getCredential(subject));
			HttpServletRequest req = (HttpServletRequest) context.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			try {
				assertion.validateAssertion(new BasicAssertionValidator(), req.getRequestURL().toString(), req.getRequestURL().toString());
			} catch (ValidationException e) {
				throw new SOAPFaultException(SOAPFactory.newInstance().createFault(e.getMessage(), new QName(WSSecurityConstants.WSSE_NS, "InvalidSecurityToken")));
			}
			
			return input;
		} catch (FrameworkMismatchFault e) {
			throw e;
		} catch (XWSSecurityException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		} catch (SOAPException e) {
			throw new RuntimeException(e);
		} 
	}
	
	private Assertion getCredential(Subject subject) {
		for (Object o : subject.getPublicCredentials()) {
			if (o instanceof XMLStreamReader) {
				String xml = printCredential((XMLStreamReader) o);
				try {
					XMLObject obj = SAMLUtil.unmarshallElementFromString(xml);
					if (obj instanceof Assertion) {
						return (Assertion) obj;
					}
				} catch (Exception e) {
					log.error("Unable to unmarshall subject: " + xml, e);
				}
			}
		}
		throw new RuntimeException("No assertion in principal");
	}
	
	private String printCredential(XMLStreamReader cred) {
		log.info("Credential: " + cred);
		
		return new StAXOMBuilder(cred).getDocumentElement().toString();
	}

	@WebMethod
	public String requestInteract(
			@WebParam(name="UserInteraction", header=true, targetNamespace="urn:liberty:sb:2006-08") UserInteraction interact,
			@WebParam(name="Framework", header=true, targetNamespace="urn:liberty:sb:2006-08") Framework framework,
			@WebParam(name="user", targetNamespace="http://provider.poc.saml.itst.dk/") String user) throws RequestToInteractFault {
		FrameworkMismatchFault.throwIfNecessary(framework, context.getMessageContext());
		
		String info = InfoRepository.getInfo(user);
		if (info == null) {
			if (interact == null) {
				throw new RuntimeException("Missing info, and no UserInteraction");
			}
			HttpServletRequest req = (HttpServletRequest) context.getMessageContext().get(MessageContext.SERVLET_REQUEST);
			StringBuilder url = new StringBuilder(req.getScheme()).append("://").append(req.getHeader("Host")).append(req.getContextPath()).append("/interact.jsp");
			throw new RequestToInteractFault("User information is needed to complete request (this message was sent by poc-provider)", url.toString());
		} else {
			return info;
		}
	}

	public static void main(String[] args) {
		Endpoint.publish("http://recht-laptop:8880/poc-provider/ProviderService", new Provider());
	}
}
