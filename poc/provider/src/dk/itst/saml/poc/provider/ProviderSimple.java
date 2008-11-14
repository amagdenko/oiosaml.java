package dk.itst.saml.poc.provider;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.ws.soap.Addressing;

import dk.itst.saml.poc.idws.Framework;

@WebService
@Addressing
@SOAPBinding(style=SOAPBinding.Style.DOCUMENT)
public class ProviderSimple {

	@WebMethod(action="http://provider.poc.saml.itst.dk/ProviderSimple/echoRequest")
	public @WebResult(name="output", targetNamespace="http://provider.poc.saml.itst.dk/") String echo(
			@WebParam(name="Framework", header=true, targetNamespace="urn:liberty:sb:2006-08") Framework framework, 
			@WebParam(name="input", targetNamespace="http://provider.poc.saml.itst.dk/") String input) {
		return input;
	}
} 
