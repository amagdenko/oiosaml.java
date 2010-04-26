package dk.itst.oiosaml.client;

import javax.swing.JFileChooser;


import groovy.swing.SwingBuilder;
import javax.swing.WindowConstants as WC;

import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.ReplyTo;
import org.opensaml.ws.wsaddressing.To;
import org.opensaml.ws.wssecurity.Password;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.Username;
import org.opensaml.ws.wssecurity.UsernameToken;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.trust.ResultHandler;
import dk.itst.oiosaml.trust.SigningPolicy;
import dk.itst.oiosaml.trust.TrustBootstrap;
import dk.itst.oiosaml.trust.TrustClient;

class Client {
	
	static def swing
	
	static main(args) {
		def model = new ClientModel()
		swing = SwingBuilder.build() {
			frame(title: 'OIOIDWS Test Client', size: [300, 700], visible: true, defaultCloseOperation: WC.EXIT_ON_CLOSE) {
				borderLayout()
				panel(constraints: NORTH, layout: gridLayout(cols: 2, rows: 8)) {
					label 'Local STS URL: '
					textField(text: bind(target: model, targetProperty: 'localStsUrl', source: model, sourceProperty: 'localStsUrl'))

					label 'Username: '
					textField(text: bind(target: model, targetProperty: 'username', source: model, sourceProperty: 'username'))
					
					label 'Password: '
					textField(text: bind(target: model, targetProperty: 'password', source: model, sourceProperty: 'password'))

					label 'Service STS URL: '
					textField(text: bind(target: model, targetProperty: 'serviceStsUrl', source: model, sourceProperty: 'serviceStsUrl'))

					label 'Service URL: '
					textField(text: bind(target: model, targetProperty: 'serviceUrl', source: model, sourceProperty: 'serviceUrl'))

					label 'User certificate: '
					button(label: 'Select', actionPerformed: {
						def fc = fileChooser(dialogTitle: 'Select certificate', fileSelectionMode: JFileChooser.FILES_ONLY)
						if (fc.showOpenDialog() == JFileChooser.APPROVE_OPTION) {
							model.certificate = fc.selectedFile
						}
					})
					
					label 'Keystore password'
					textField(text: bind(target: model, targetProperty: 'certificatePassword', source: model, sourceProperty: 'certificatePassword'))
					

					label 'Execute reqest'
					button (label: 'Execute', actionPerformed: {  
						doOutside {
							execute(model)
						}
					})
				}
				scrollPane(constraints: CENTER) {
					editorPane(id: 'console', editable: false)
				}
			}
		}
	}
	
	static execute(model) {
		DefaultBootstrap.bootstrap();
		TrustBootstrap.bootstrap();
		
		print("Sending request to ${model.localStsUrl}")
		
		def rep = new CredentialRepository()
		def credential = rep.getCredential(model.certificate, model.certificatePassword)
		
		def client = new TrustClient(null, credential, null)
		client.appliesTo = model.serviceStsUrl
		client.useReferenceForDelegateToken = false
		client.useActAs = true
		client.endpoint = model.localStsUrl
		
		UsernameToken ut = SAMLUtil.buildXMLObject(UsernameToken.class);
		Username username = SAMLUtil.buildXMLObject(Username.class);
		username.setValue(model.username);
		ut.setUsername(username);
		
		Password pw = SAMLUtil.buildXMLObject(Password.class);
		pw.setValue(model.password);
		ut.getUnknownXMLObjects().add(pw);
		
		client.setSecurityToken(ut);
		
		def token = client.getToken()
		print("Local STS token: ")
		print(new OIOAssertion(token).toXML())
		
		print("Fetching remote STS token at ${model.serviceStsUrl}")
		client = new TrustClient(null, credential, null)
		client.appliesTo = model.serviceUrl
		client.useReferenceForDelegateToken = false
		client.useActAs = true
		client.delegateToken = token
		client.endpoint = model.serviceStsUrl
		print("Remote STS token: ")
		print(new OIOAssertion(client.getToken()).toXML())
		
		def sc = client.serviceClient
		SigningPolicy sp = new SigningPolicy(true);
		sp.addPolicy(To.ELEMENT_NAME, true);
		sp.addPolicy(MessageID.ELEMENT_NAME, true);
		sp.addPolicy(Action.ELEMENT_NAME, true);
		sp.addPolicy(Body.DEFAULT_ELEMENT_NAME, true);
		sp.addPolicy(ReplyTo.ELEMENT_NAME, true);
		sp.addPolicy(Timestamp.ELEMENT_NAME, true);
		sc.signingPolicy = sp;
		
		sc.protectTokens = true
		
		print("Sending service request to ${model.serviceUrl}")
		def req = SAMLUtil.loadElementFromString('<ns2:Echo xmlns:ns2="http://tempuri.org/"><ns2:Structure><ns2:Value>testing</ns2:Value></ns2:Structure></ns2:Echo>')
		sc.sendRequest(req, model.serviceUrl, "http://tempuri.org/service/EchoRequest", null, new ResultHandler<Element>() {
			public void handleResult(Element result) throws Exception {
				print("Result received")
				print(XMLHelper.prettyPrintXML(result))
			}
		});
	}
	
	static print(line) {
		swing.doLater {
			console.text += line
			console.text += "\n"
		}
	}
}
