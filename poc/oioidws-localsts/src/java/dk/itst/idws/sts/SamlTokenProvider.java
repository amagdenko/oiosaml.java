/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package dk.itst.idws.sts;

import com.sun.xml.ws.api.security.trust.WSTrustException;
import com.sun.xml.ws.security.IssuedTokenContext;
import com.sun.xml.ws.security.trust.impl.DefaultSAMLTokenProvider;
import org.w3c.dom.Element;

/**
 *
 * @author recht
 */
public class SamlTokenProvider extends DefaultSAMLTokenProvider {

    @Override
    public void generateToken(IssuedTokenContext ctx) throws WSTrustException {
        ctx.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
        
        Element kiEle = (Element)ctx.getOtherProperties().get("ConfirmationKeyInfo");
        if (!"KeyInfo".equals(kiEle.getLocalName())) {
            ctx.getOtherProperties().remove("ConfirmationKeyInfo");
        }

        super.generateToken(ctx);
    }



}
