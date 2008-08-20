package dk.itst.oiosaml.authz;

public class IllegalFormatException extends RuntimeException {

	public IllegalFormatException(String fault, Throwable cause) {
		super(fault, cause);
	}

	public IllegalFormatException(String message) {
		super(message);
	}
}
