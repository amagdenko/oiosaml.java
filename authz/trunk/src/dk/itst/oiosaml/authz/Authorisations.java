package dk.itst.oiosaml.authz;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Authorisations {
	private static final Logger log = Logger.getLogger(Authorisations.class);
	
	private final Set<Key> authorisations = new HashSet<Key>();
	
	public Authorisations(String xml) {
		Utils.checkNotNull(xml, "xml");
		if (log.isDebugEnabled()) log.debug("Parsing authorisations: " + xml);

		parseAuthorisations(Utils.parse(xml, "brs.xsd"));
	}
	
	public Authorisations(Element xml) {
		parseAuthorisations(xml);
	}
	
	private void parseAuthorisations(Element xml) {
		if (!Constants.ELEMENT_AUTHORISATIONS.equals(xml.getLocalName())) {
			throw new IllegalFormatException("Top element must be Authorisations. Was " + xml.getLocalName());
		}
		
		NodeList authorisations = xml.getChildNodes();
		if (log.isDebugEnabled()) log.debug("Parsing " + authorisations.getLength()  + " authorisations");
		
		for (int i = 0; i < authorisations.getLength(); i++) {
			if (!(authorisations.item(i) instanceof Element)) continue;
			
			Element authorisation = (Element) authorisations.item(i);
			
			String resource = authorisation.getAttribute(Constants.ATTRIBUTE_RESOURCE);
			checkResourcePrefix(resource);
			
			NodeList privileges = authorisation.getChildNodes();
			for (int j = 0; j < privileges.getLength(); j++) {
				if (!(authorisations.item(j) instanceof Element)) continue;
				
				Element privilege = (Element) privileges.item(j);
				
				this.authorisations.add(new Key(resource, privilege.getTextContent().trim()));
			}
		}
	}
	
	private void checkResourcePrefix(String resource) {
		log.debug("Checking resource prefix for " + resource);
		
		if (!(resource.startsWith(Constants.RESOURCE_CVR_NUMBER_PREFIX) || 
				resource.startsWith(Constants.RESOURCE_PNUMER_PREFIX))) {
			throw new UnsupportedResourceException(resource, null);
		}
	}
	
	public boolean isAuthorised(String resource, String privilege) {
		Utils.checkNotNull(resource, "resource");
		Utils.checkNotNull(privilege, "privilege");
		
		return authorisations.contains(new Key(resource, privilege));
	}
	
	
	private static class Key {
		private final String resource;
		private final String privilege;

		public Key(String resource, String privilege) {
			this.resource = resource;
			this.privilege = privilege;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + privilege.hashCode();
			result = prime * result + resource.hashCode();
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) return true;
			if (obj == null) return false;
			if (getClass() != obj.getClass()) return false;
			Key other = (Key) obj;
			if (!privilege.equals(other.privilege))
				return false;
			if (!resource.equals(other.resource))
				return false;
			return true;
		}
	}

}
