package dk.itst.saml.poc;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;

public class SAMLCallback implements CallbackHandler {    
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i=0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof com.sun.xml.wss.impl.callback.SAMLCallback) {
                try{
                    com.sun.xml.wss.impl.callback.SAMLCallback samlCallback = (com.sun.xml.wss.impl.callback.SAMLCallback)callbacks[i];
                    System.out.println(samlCallback.getRuntimeProperties());
                    System.out.println("Confirmation method: " + samlCallback.getConfirmationMethod());
                    System.out.println("SAML Callback: " + samlCallback);
                    samlCallback.setAssertionElement(SAMLUtil.loadElementFromString(XMLHelper.nodeToString(AssertionHolder.get())));
                } catch(Exception ex) {
                        ex.printStackTrace();
                }
            } else {
                throw new UnsupportedCallbackException(null, "Unsupported Callback Type Encountered");
            }
        }
    }
}
