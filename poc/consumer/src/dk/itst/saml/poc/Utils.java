package dk.itst.saml.poc;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.opensaml.xml.XMLObject;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;

public class Utils {
	private static JAXBContext jc;
	static {
		try {
			jc = JAXBContext.newInstance("dk.itst.saml.poc.provider:liberty.sb._2006_08");
		} catch (JAXBException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static JAXBContext getJAXBContext() {
		return jc;
	}

	public static Object unmarshall(XMLObject xml) {
		Element element = SAMLUtil.marshallObject(xml);

		try {
			Unmarshaller unmarshaller = jc.createUnmarshaller();
			
			JAXBElement<?> object = (JAXBElement<?>) unmarshaller.unmarshal(element);
			return object.getValue();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
}
