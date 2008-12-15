package dk.itst.saml.poc.provider;

import javax.annotation.Resource;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.xml.stream.XMLStreamReader;
import javax.xml.ws.Endpoint;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;

import com.sun.xml.wss.SubjectAccessor;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.model.validation.BasicAssertionValidator;
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
			assertion.validateAssertion(new BasicAssertionValidator(), req.getRequestURL().toString(), req.getRequestURL().toString());
			
			return input;
		} catch (FrameworkMismatchFault e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
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

	/*
	private void validateAssertion(Subject subject, StringBuffer sb)
			throws ParserConfigurationException,
			TransformerFactoryConfigurationError,
			TransformerConfigurationException, TransformerException,
			MalformedURLException, IOException {
		XMLStreamReader r = (XMLStreamReader) subject.getPublicCredentials().iterator().next();
		DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
		df.setNamespaceAware(true);
		DocumentBuilder builder = df.newDocumentBuilder();
		Document doc = builder.newDocument();
		
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer t = tf.newTransformer();
		t.transform(new StAXSource(r, true),new DOMResult(doc));
		
		STSClient client = new STSClient("http://tri-test1.trifork.com:8080/sts/");
		client.registerSecurityTokenReference(new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion"), KeyIdentifierTokenReference.SAML20_TOKEN_TYPE, 
				new KeyIdentifierTokenReference(KeyIdentifierTokenReference.SAML20_TOKEN_TYPE, KeyIdentifierTokenReference.SAML20_VALUE_TYPE, new IdProvider() {
					public String obtainId(Element e) throws STSClientException {
						log.debug("Resolving id for " + e);
						return e.getAttribute("ID");
					}
				}));

		BasicX509Credential credential = Utils.getCredential("/home/recht/download/TestVOCES1.pfx", "Test1234");

		RequestSecurityTokenData vd = client.createValidateData();
		vd.setTokenType(KeyIdentifierTokenReference.SAML20_TOKEN_TYPE);
		STSResponse response = client.makeRequest(vd, doc.getDocumentElement(), null, KeyIdentifierTokenReference.SAML20_TOKEN_TYPE, new X500PrivateCredential(credential.getEntityCertificate(), credential.getPrivateKey()));
		
		sb.append("Validate response: ").append(response).append("\n");
		sb.append("Fail: ").append(response.isFault()).append("\n");
		if (!response.isFault()) {
			sb.append("Message: ").append(Utils.beautifyAndHtmlXML(XMLHelper.nodeToString(response.getStsMessage().toDocument().getDocumentElement()), "&nbsp;&nbsp;&nbsp;&nbsp;")).append("\n");
		} else {
			sb.append("Fail message: ").append(response.getSoapFault().getDetail()).append("\n");
		}
	}*/

	public static void main(String[] args) {
		Endpoint.publish("http://recht-laptop:8880/poc-provider/ProviderService", new Provider());
	}
}
