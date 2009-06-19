package dk.sst.oiosaml.wsfed.service;

import org.opensaml.ws.soap.soap11.Fault;

public class LoginException extends RuntimeException {
	
	private final Fault fault;

	public LoginException(String msg, Fault fault) {
		super(msg);
		this.fault = fault;
	}
	
	public Fault getFault() {
		return fault;
	}
}
