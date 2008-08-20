package dk.itst.oiosaml.authz;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;


public class ProtectionsTest {
	
	@Test
	public void testLoad() {
		String xml = "<Protections xmlns=\"http://www.itst.dk/oiosaml/authz/2008/08/\"></Protections>";
		new Protections(xml);
	}
	
	@Test(expected=IllegalFormatException.class)
	public void failOnIllegalXML() {
		String xml = "<Protections></Protections>";
		new Protections(xml);
	}
	
	@Test
	public void testIsAuthorised() {
		Protections p = getProtections();
		Authorisations a = getAuthorisations();
		
		assertTrue(p.isAuthorised("urn:dk:cvr:cVRnumberIdentifier:13124930", "/admin/testing", "GET", a));

		assertTrue(p.isAuthorised("urn:dk:cvr:cVRnumberIdentifier:13124930", "/testing", "GET", a));
		assertFalse(p.isAuthorised("urn:dk:cvr:cVRnumberIdentifier:13124930", "/testing", "POST", a));
		
		assertFalse(p.isAuthorised("urn:dk:cvr:cVRnumberIdentifier:99999999", "/admin/testing", "GET", a));
		
		assertFalse(p.isAuthorised("urn:dk:cvr:productionUnitIdentifier:1029275212", "/admin/testing", "GET", a));
	}

	private Protections getProtections() {
		try {
			return new Protections(IOUtils.toString(getClass().getResourceAsStream("protections.xml")));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private Authorisations getAuthorisations() {
		try {
			return new Authorisations(IOUtils.toString(getClass().getResourceAsStream("authorisations.xml")));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}