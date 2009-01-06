package dk.itst.saml.poc.idws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name="Framework", namespace="urn:liberty:sb:2006-08")
@XmlType(name="Framework", namespace="urn:liberty:sb:2006-08")
@XmlAccessorType(XmlAccessType.FIELD)
public class Framework {

	@XmlAttribute(name="profile", namespace="urn:liberty:sb:profile", required=true)
	private String profile;
	
	@XmlAttribute(name="version", required=true)
	private String version;
	
	@XmlAttribute(name="mustUnderstand", namespace="http://schemas.xmlsoap.org/soap/envelope/")
	private String mustUnderstand;

	public String getProfile() {
		return profile;
	}

	public void setProfile(String profile) {
		this.profile = profile;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getMustUnderstand() {
		return mustUnderstand;
	}

	public void setMustUnderstand(String mustUnderstand) {
		this.mustUnderstand = mustUnderstand;
	}
}
