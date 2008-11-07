package dk.itst.oiosaml.trust;

import org.opensaml.xml.XMLObject;

public interface ResultHandler {
	
	public void handleResult(XMLObject result);

}
