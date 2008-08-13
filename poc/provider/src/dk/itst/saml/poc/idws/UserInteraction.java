package dk.itst.saml.poc.idws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name="UserInteraction", namespace="urn:liberty:sb:2006-08")
@XmlType(name="UserInteraction", namespace="urn:liberty:sb:2006-08")
@XmlAccessorType(XmlAccessType.FIELD)
public class UserInteraction {
	
	@XmlAttribute(name="interact")
	private String interact = "InteractIfNeeded";
	
	@XmlAttribute(name="redirect")
	private boolean redirect = true;

	public String getInteract() {
		return interact;
	}

	public void setInteract(String interact) {
		this.interact = interact;
	}

	public boolean isRedirect() {
		return redirect;
	}

	public void setRedirect(boolean redirect) {
		this.redirect = redirect;
	}

	
}
