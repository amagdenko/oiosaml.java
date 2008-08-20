package dk.itst.oiosaml.authz;

public class UnsupportedResourceException extends RuntimeException {
	
	public UnsupportedResourceException(String resource, String original) {
		super("Unsupported resource: " + resource);
	}
}
