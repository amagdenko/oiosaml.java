package dk.itst.saml.poc.provider;

import java.util.ArrayList;
import java.util.Collection;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name="Structure", namespace="http://provider.poc.saml.itst.dk/")
@XmlType(name="Structure", namespace="http://provider.poc.saml.itst.dk/", propOrder = { "structure", "value"})
@XmlAccessorType(XmlAccessType.FIELD)
public class Structure {

	@XmlElement(name="structure", namespace="http://provider.poc.saml.itst.dk/")
	private Collection<Structure> structure = new ArrayList<Structure>();

	@XmlElement(name="value", namespace="http://provider.poc.saml.itst.dk/")
	private String value;

	public void addStructure(Structure s) {
		this.structure.add(s);
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}
	
	
}
