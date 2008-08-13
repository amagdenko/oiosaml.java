/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package dk.itst.saml.sts;

import com.sun.xml.ws.security.trust.sts.BaseSTSImpl;
import javax.annotation.Resource;
import javax.xml.transform.Source;
import javax.xml.ws.Provider;
import javax.xml.ws.Service.Mode;
import javax.xml.ws.BindingType;
import javax.xml.ws.Endpoint;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceProvider;
import javax.xml.ws.handler.MessageContext;

/**
 *
 * @author recht
 */
//@WebServiceProvider(serviceName = "TokenServiceService", portName = "ITokenServiceService_Port", targetNamespace = "http://tempuri.org/", wsdlLocation = "WEB-INF/wsdl/TokenServiceService.wsdl")
@WebServiceProvider(serviceName = "TokenServiceService", portName = "ITokenServiceService_Port", targetNamespace = "http://tempuri.org/", wsdlLocation = "TokenServiceService.wsdl")
@ServiceMode(value = Mode.PAYLOAD)
@BindingType(value="http://java.sun.com/xml/ns/jaxws/2003/05/soap/bindings/HTTP/")
public class TokenService extends BaseSTSImpl implements Provider<Source> {
    @Resource
    WebServiceContext context;

    public Source invoke(Source rstElement) {
        return super.invoke(rstElement);
    }

    protected MessageContext getMessageContext() {
        MessageContext msgCtx = context.getMessageContext();
        return msgCtx;
    }

    public static void main(String[] args) {
		Endpoint.publish("http://localhost:8880/sts/TokenServiceService", new TokenService());
	}
}
