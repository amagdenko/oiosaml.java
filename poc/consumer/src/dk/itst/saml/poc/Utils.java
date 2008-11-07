package dk.itst.saml.poc;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Holder;

import org.apache.log4j.Logger;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.trust.ResultHandler;
import dk.itst.oiosaml.trust.TrustClient;

public class Utils {
	private static final Logger log = Logger.getLogger(Utils.class);

	public static Element marshall(Object o) { 
		try {
			JAXBContext jc = JAXBContext.newInstance("dk.itst.saml.poc.provider:liberty.sb._2006_08");
			Marshaller marshaller = jc.createMarshaller();
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().newDocument();

			Object factory = Class.forName(o.getClass().getPackage().getName() + ".ObjectFactory").newInstance();
			String name = o.getClass().getName();
			Method m = factory.getClass().getDeclaredMethod("create" + name.substring(name.lastIndexOf('.') + 1), o.getClass());
			Object jaxbElement = m.invoke(factory, o);
			
			marshaller.marshal(jaxbElement, doc);
			
			return doc.getDocumentElement();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static Object unmarshall(XMLObject xml) {
		Element element = SAMLUtil.marshallObject(xml);

		try {
			JAXBContext jc = JAXBContext.newInstance("dk.itst.saml.poc.provider:liberty.sb._2006_08");
			Unmarshaller unmarshaller = jc.createUnmarshaller();
			
			JAXBElement<?> object = (JAXBElement<?>) unmarshaller.unmarshal(element);
			return object.getValue();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static Object request(Object request, TrustClient client, BindingProvider bp, String action) {
		Element body = Utils.marshall(request);
		log.debug("Sending request " + XMLHelper.nodeToString(body));
		
		final Holder<XMLObject> holder = new Holder<XMLObject>();
		try {
			client.sendRequest(body, 
					(String) bp.getRequestContext().get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY), 
					action, null, new ResultHandler() {
						public void handleResult(XMLObject arg0) {
							holder.value = arg0;
						}
			});
		} catch (InvocationTargetException e) {
			throw new RuntimeException(e);
		}

		return unmarshall(holder.value);
	}
}
