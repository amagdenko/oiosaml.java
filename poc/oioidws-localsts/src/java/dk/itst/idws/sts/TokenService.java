/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package dk.itst.idws.sts;

import javax.annotation.Resource;
import javax.xml.transform.Source;
import javax.xml.ws.Provider;
import javax.xml.ws.Service.Mode;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceProvider;
import javax.xml.ws.handler.MessageContext;

/**
 *
 * @author recht
 */
@WebServiceProvider(serviceName = "TokenServiceService", portName = "ITokenServiceService_Port", targetNamespace = "http://tempuri.org/", wsdlLocation = "WEB-INF/wsdl/TokenService/TokenServiceService.wsdl")
@ServiceMode(value = Mode.PAYLOAD)
public class TokenService extends com.sun.xml.ws.security.trust.sts.BaseSTSImpl implements Provider<Source> {
    @Resource
    WebServiceContext context;

    public Source invoke(Source rstElement) {
        return super.invoke(rstElement);
    }

    protected MessageContext getMessageContext() {
        MessageContext msgCtx = context.getMessageContext();
        return msgCtx;
    }

}
