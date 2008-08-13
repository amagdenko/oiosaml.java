package dk.itst.saml.poc;

import org.w3c.dom.Element;

public class AssertionHolder {
	private static ThreadLocal<Element> assertion = new ThreadLocal<Element>();
	
	public static void set(Element e) {
		assertion.set(e);
	}
	
	public static Element get() {
		return assertion.get();
	}
}
