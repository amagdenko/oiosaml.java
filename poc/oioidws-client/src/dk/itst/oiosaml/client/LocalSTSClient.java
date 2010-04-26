package dk.itst.oiosaml.client;

import org.opensaml.ws.wssecurity.Password;
import org.opensaml.ws.wssecurity.Username;
import org.opensaml.ws.wssecurity.UsernameToken;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.trust.TrustClient;

public class LocalSTSClient {

	public static void main(String[] args) {
		ClientModel model = new ClientModel();
		CredentialRepository rep = new CredentialRepository();
		BasicX509Credential credential = rep.getCredential(model.getCertificate(), model.getCertificatePassword());

		TrustClient client = new TrustClient(null, credential, null);
		client.setAppliesTo(model.getServiceUrl());
		client.setUseReferenceForDelegateToken(false);
		client.setUseActAs(false);
		client.setEndpoint(model.getLocalStsUrl());

		UsernameToken ut = SAMLUtil.buildXMLObject(UsernameToken.class);
		Username username = SAMLUtil.buildXMLObject(Username.class);
		username.setValue("jre");
		ut.setUsername(username);
		
		Password pw = SAMLUtil.buildXMLObject(Password.class);
		pw.setValue("dild42");
		ut.getUnknownXMLObjects().add(pw);
		
		client.setSecurityToken(ut);
		
		client.getToken();
	}
}
