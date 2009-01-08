package dk.itst.saml.poc.provider;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.ws.Action;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.soap.Addressing;

import dk.itst.saml.poc.idws.Framework;

@WebService
@SOAPBinding(style=SOAPBinding.Style.DOCUMENT, use = SOAPBinding.Use.LITERAL)
@HandlerChain(file="handlers.xml")
@Addressing
public class GenevaProvider {
	@Resource
	private WebServiceContext context;

	@Action(input="http://provider.poc.saml.itst.dk/Provider/echoRequest", output="http://provider.poc.saml.itst.dk/Provider/echoResponse")
	@WebMethod(action="http://provider.poc.saml.itst.dk/Provider/echoRequest")
	public @WebResult(name="structure", targetNamespace="http://provider.poc.saml.itst.dk/") Structure echo(
			@WebParam(name="Framework", header=true, targetNamespace="urn:liberty:sb:2006-08") Framework framework, 
			@WebParam(name="structure", targetNamespace="http://provider.poc.saml.itst.dk/") Structure input) {
			return Provider.process(input, context, framework);
	}
}
