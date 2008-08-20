package dk.itst.oiosaml.authz;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;


public class AuthorisationsTest {
	
	@Test
	public void testAuthorisationsFromString() {
		String auth = "<Authorisations xmlns=\"http://www.eogs.dk/2007/07/brs\"></Authorisations>";
		Authorisations a = new Authorisations(auth);
		
		assertFalse(a.isAuthorised("test", "test"));
	}
	
	
	@Test(expected=UnsupportedResourceException.class)
	public void onlyAcceptValidResourcePrefixes() {
		String auth = "<Authorisations xmlns=\"http://www.eogs.dk/2007/07/brs\"><Authorisation resource=\"urn:testing\"><Privilege>test</Privilege></Authorisation></Authorisations>";
		new Authorisations(auth);
	}
	
	@Test(expected=IllegalFormatException.class)
	public void rejectInvalidXML() {
		String auth = "<Authorisations></Authorisations>";
		new Authorisations(auth);
	}
	
	@Test(expected=IllegalFormatException.class)
	public void rejectMalformedXML() {
		String auth = "<xml></authorisations>";
		new Authorisations(auth);
	}
	
	@Test
	public void testIsAuthorised() {
		Authorisations a = getAuthorisations();
		assertTrue(a.isAuthorised(Constants.RESOURCE_CVR_NUMBER_PREFIX + "13124930", "urn:dk:serviceprovider1:privilege:fileSecretStatistics"));
		assertTrue(a.isAuthorised(Constants.RESOURCE_CVR_NUMBER_PREFIX + "13124930", "urn:dk:serviceprovider1:privilege:administerTaxes"));
		
		assertTrue(a.isAuthorised(Constants.RESOURCE_PNUMER_PREFIX + "1029275212", "urn:dk:serviceprovider1:privilege:viewEmployeeInformation"));
		
		assertFalse(a.isAuthorised(Constants.RESOURCE_CVR_NUMBER_PREFIX + "13124930", "urn:dk:serviceprovider1:privilege:file"));
	}

	private Authorisations getAuthorisations() {
		try {
			return new Authorisations(IOUtils.toString(getClass().getResourceAsStream("authorisations.xml")));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
