package dk.itst.saml.poc;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.sp.util.BRSUtil;

public class SAMLCallback implements CallbackHandler {    
    public static final String holderOfKeyConfirmation = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";
    
    public static final String senderVouchesConfirmation = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";
    
    public static final String holderOfKeyConfirmation_saml20 = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
    
    public static final String senderVouchesConfirmation_saml20 = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
    
    public SAMLCallback() {
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i=0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof com.sun.xml.wss.impl.callback.SAMLCallback) {
                try{
                    com.sun.xml.wss.impl.callback.SAMLCallback samlCallback = (com.sun.xml.wss.impl.callback.SAMLCallback)callbacks[i];
                    System.out.println(samlCallback.getRuntimeProperties());
                    System.out.println("Confirmation method: " + samlCallback.getConfirmationMethod());
                    System.out.println("SAML Callback: " + samlCallback);
                    samlCallback.setAssertionElement(createSVSAMLAssertion());
//                    if (samlCallback.getConfirmationMethod().equals(com.sun.xml.wss.impl.callback.SAMLCallback.SV_ASSERTION_TYPE)) {
//                            samlCallback.setAssertionElement(createSVSAMLAssertion());
//                    } else {
//                            throw new Exception("SAML Assertion Type is not matched: " + samlCallback.getConfirmationMethod());
//                    }
                } catch(Exception ex) {
                        ex.printStackTrace();
                }
            } else {
                throw new UnsupportedCallbackException(null, "Unsupported Callback Type Encountered");
            }
        }
    }
    
    private static Element createSVSAMLAssertion() {
    	return BRSUtil.loadElementFromString(XMLHelper.nodeToString(AssertionHolder.get()));
    }
}
