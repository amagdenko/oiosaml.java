package dk.itst.saml.sts;

import static org.junit.Assert.*;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;

import org.junit.Test;

import com.sun.xml.ws.security.trust.WSTrustElementFactory;
import com.sun.xml.ws.security.trust.WSTrustVersion;
import com.sun.xml.ws.security.trust.elements.RequestSecurityToken;
import com.sun.xml.ws.security.trust.impl.wssx.bindings.RequestSecurityTokenType;


public class JabxTest {

	@Test
	public void testJaxb() throws Exception {
		
		
        final WSTrustElementFactory eleFac = WSTrustElementFactory.newInstance(WSTrustVersion.WS_TRUST_13);
        JAXBContext ctx = WSTrustElementFactory.getContext(WSTrustVersion.WS_TRUST_13);
        System.out.println(ctx);

        StreamSource src = new StreamSource(getClass().getResourceAsStream("request.xml"));

        Unmarshaller unmarshaller = ctx.createUnmarshaller();
        System.out.println(unmarshaller);
        JAXBElement<RequestSecurityTokenType> rstType = unmarshaller.unmarshal(src, RequestSecurityTokenType.class);
        
        System.out.println(rstType);
        System.out.println(rstType.getValue());
        
        RequestSecurityTokenType val = rstType.getValue();
        System.out.println(val.getAny());
        
        for (Object o : val.getAny()) {
        	System.out.println(o.getClass());
        }
        
//		final RequestSecurityToken rst = eleFac.createRSTFrom(src);         
//
//        System.out.println(rst);
//        System.out.println(rst.get);
	}
}
