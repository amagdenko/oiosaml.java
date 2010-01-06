package dk.itst.oiosaml.sts;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import com.sun.xml.ws.api.security.trust.Claims;
import com.sun.xml.ws.api.security.trust.STSAttributeProvider;
import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.Attribute;
import com.sun.xml.wss.saml.SAMLAssertionFactory;
import com.sun.xml.wss.saml.assertion.saml20.jaxb20.AttributeStatement;

public class AttributeProvider implements STSAttributeProvider {

	public Map<QName, List<String>> getClaimedAttributes(Subject subject, String appliesTo, String tokenType, Claims claims) {
		Map<QName, List<String>> res = new HashMap<QName, List<String>>();
		Assertion assertion = getSubject(claims);
		if (assertion != null) {
			AttributeStatement attrs = getAttributes(assertion);
			for (Attribute attr : attrs.getAttributes()) {
				if (!hasClaim(attr.getName(), claims)) continue;
				
				List<String> values = new ArrayList<String>();
				for (Object val : attr.getAttributes()) {
					values.add(val.toString());
				}
				res.put(new QName(attr.getName()), values);
			}
		}
		
		res.put(new QName(assertion.getSubject().getNameId().getNameQualifier(), 
				STSAttributeProvider.NAME_IDENTIFIER), Collections.singletonList(assertion.getSubject().getNameId().getValue()));
		return res;
	}
	
	private boolean hasClaim(String name, Claims claims) {
		if (claims == null) return true;
		if (claims.getAny() == null || claims.getDialect() == null) return true;
		
		for (Object o : claims.getAny()) {
			if (o instanceof Element) {
				Element e = (Element) o;
				if (name.equals(e.getTextContent())) {
					return true;
				}
			}
		}
		return false;
	}

	private AttributeStatement getAttributes(Assertion assertion) {
		for (Object st : assertion.getStatements()) {
			if (st instanceof AttributeStatement) {
				return (AttributeStatement) st;
			}
		}
		return null;
	}
	
	private Assertion getSubject(Claims claims) {
		Subject subject = null;
		for (Object prop : claims.getSupportingProperties()) {
			if (prop instanceof Subject) {
				subject = (Subject) prop;
			}
		}
		if (subject != null) {
			Set<Element> creds = subject.getPublicCredentials(Element.class);
			if (!creds.isEmpty()) {
				Element assertion = creds.iterator().next();
				try {
					Assertion saml = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML2_0).createAssertion(assertion);
					return saml;
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
		return null;
	}

}
