package dk.itst.saml.poc.idws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.ws.WebFault;

@WebFault(name="RedirectRequest", targetNamespace="urn:liberty:sb:2006-08", faultBean="dk.itst.saml.poc.provider.RequestToInteractFault$Bean")
public class RequestToInteractFault extends Exception {

	private final Bean info;

	public RequestToInteractFault(String message, String url) {
		this(message, new Bean(url, message));
	}

	public RequestToInteractFault(String message, Bean info) {
		this(message, info, null);
	}
	
	public RequestToInteractFault(String message, Bean info, Throwable cause) {
		super(message, cause);
		this.info = info;
	}
	
	public Bean getFaultInfo() {
		return info;
	}
	
	
	@XmlRootElement(name="RedirectRequest", namespace="urn:liberty:sb:2006-08")
	@XmlType(name="RedirectRequest", namespace="urn:liberty:sb:2006-08")
	@XmlAccessorType(XmlAccessType.FIELD)
	public static class Bean {
		
		@XmlAttribute(name="RedirectURL")
		private String url;
		
		private String message;
		
		public Bean() {
			
		}
		
		public Bean(String url, String message) {
			this.url = url;
			this.message = message;
		}
	}
}
