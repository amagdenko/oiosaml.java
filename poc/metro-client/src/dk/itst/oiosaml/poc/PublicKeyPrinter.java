package dk.itst.oiosaml.poc;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;

public class PublicKeyPrinter {

	public static void main(String[] args) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
//		ks.load(new FileInputStream("/home/recht/download/TestVOCES1.pfx"), "Test1234".toCharArray());
		ks.load(new FileInputStream("/home/recht/eclipse/sts-client/src/META-INF/TestMOCES1.pfx"), "Test1234".toCharArray());
		
		Enumeration<String> aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			
			System.out.println(ks.getCertificate(alias).getPublicKey());
		}
	}
}
