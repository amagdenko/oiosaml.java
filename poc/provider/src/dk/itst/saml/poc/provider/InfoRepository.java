package dk.itst.saml.poc.provider;

import java.util.HashMap;
import java.util.Map;

public class InfoRepository {

	private static Map<String, String> info = new HashMap<String, String>();
	
	public static String getInfo(String user) {
		return info.get(user);
	}
	
	public static void setInfo(String user, String info) {
		InfoRepository.info.put(user, info);
	}
}
