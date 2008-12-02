package dk.itst.oiosaml.trust;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;


@XmlRootElement(name="blah", namespace="urn:testing")
public class TestBean {

	@XmlElement(name="more", namespace="urn:testing")
	private String more;

	public String getMore() {
		return more;
	}
}
