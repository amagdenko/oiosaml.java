package dk.itst.oiosaml.authz;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Protections {
	private static final Logger log = Logger.getLogger(Protections.class);
	
	private static final String PROTECTIONS_DEFAULT = "default";
	private static final String RESOURCE_NAME = "name";
	private static final String URL_PATH = "path";
	private static final String URL_METHOD = "method";
	private static final String PRIVILEGE_NAME = "name";

	private boolean defaultAllow = true;
	
	private final Map<String, List<Url>> protections = new HashMap<String, List<Url>>();

	public Protections(String xml) {
		Utils.checkNotNull(xml, "xml");
		Element element = Utils.parse(xml, "protection.xsd");
		parseProtections(element);
	}
	
	private void parseProtections(Element element) {
		String defaultPolicy = element.getAttribute(PROTECTIONS_DEFAULT);
		if ("deny".equals(defaultPolicy)) {
			defaultAllow = false;
		}
		
		NodeList resources = element.getChildNodes();
		if (log.isDebugEnabled()) log.debug("Parsing " + resources.getLength() + " resources");
		
		for (int i = 0; i < resources.getLength(); i++) {
			if (!(resources.item(i) instanceof Element)) continue;
			
			Element resource = (Element) resources.item(i);
			String resourceName = resource.getAttribute(RESOURCE_NAME);

			List<Url> urlList = new ArrayList<Url>();
			NodeList urls = resource.getChildNodes();
			for (int j = 0; j < urls.getLength(); j++) {
				if (!(urls.item(j) instanceof Element)) continue;
				
				Element url = (Element) urls.item(j);
				String path = url.getAttribute(URL_PATH);
				String method = url.getAttribute(URL_METHOD);
				if (method == null) {
					method = "*";
				}
				
				Collection<String> privileges = getPrivileges(url);
				urlList.add(new Url(path, method, privileges));
			}
			
			if (protections.containsKey(resourceName)) {
				protections.get(resourceName).addAll(urlList);
			} else {
				protections.put(resourceName, urlList);
			}
		}
		
		if (log.isDebugEnabled()) log.debug("Protections: " + protections);
	}
	
	private Collection<String> getPrivileges(Element url) {
		Set<String> res = new HashSet<String>();
		
		NodeList privs = url.getChildNodes();
		for (int i = 0; i < privs.getLength(); i++) {
			if (!(privs.item(i) instanceof Element)) continue;
			
			Element priv = (Element) privs.item(i);
			res.add(priv.getAttribute(PRIVILEGE_NAME));
		}
		
		return res;
	}

	public boolean isAuthorised(String resource, String url, String method, Authorisations auths) {
		Utils.checkNotNull(resource, "resource");
		Utils.checkNotNull(url, "url");
		Utils.checkNotNull(method, "method");
		Utils.checkNotNull(auths, "auths");
		
		List<Url> urls = protections.get(resource);
		if (urls == null) {
			return defaultAllow;
		}
		for (Url u : urls) {
			if (u.matches(url, method)) {
				Collection<String> privs = u.getPrivileges();
				if (log.isDebugEnabled()) log.debug("Found url " + u + ", required privileges: " + privs + ", available authorisations: " + auths);
				for (String priv : privs) {
					if (auths.isAuthorised(resource, priv)) {
						return true;
					}
				}
				return false;
			}
			
		}
		return defaultAllow;
	}
	
}
