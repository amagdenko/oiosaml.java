package dk.itst.saml.sts;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.ws.Provider;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceProvider;
import javax.xml.ws.Service.Mode;

import org.opensaml.ws.soap.soap11.Envelope;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.trust.OIOSoapEnvelope;

@WebServiceProvider
@ServiceMode(value=Mode.MESSAGE)
public class TokenService implements Provider<Source> {

	public Source invoke(Source request) {
		DOMResult result = new DOMResult();
		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.transform(request, result);
			
			OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElement((Element)result.getNode()));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}

}
