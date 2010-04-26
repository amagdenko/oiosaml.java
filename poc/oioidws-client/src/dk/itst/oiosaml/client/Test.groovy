package dk.itst.oiosaml.client

import org.opensaml.ws.wssecurity.Username;
import org.opensaml.ws.wssecurity.UsernameToken;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.trust.TrustClient;

class Test {

	static main(args) {
		def model = new ClientModel()

		def rep = new CredentialRepository()
		def credential = rep.getCredential(model.certificate, model.certificatePassword)
		
		def client = new TrustClient(null, credential, null)
		client.appliesTo = model.serviceStsUrl
		client.useReferenceForDelegateToken = false
		client.useActAs = false
		client.endpoint = model.localStsUrl
		
		def ut = SAMLUtil.buildXMLObject(UsernameToken.class)
		def username = SAMLUtil.buildXMLObject(Username.class)
		username.value = "fissirul"
		ut.username = username
		
		client.delegateToken = ut
		
		def token = client.getToken()
		
	}
}
