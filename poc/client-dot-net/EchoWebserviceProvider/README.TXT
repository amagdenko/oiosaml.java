OIOSAML Echo Webservice provider
-----------------------------------------------------------------------------------

Prerequesits:

Geneva Framework Beta
Vista or Windows Server 2008 OS

-----------------------------------------------------------------------------------

Installation:


1. Under IIS, add a new virtual directory and set the path to EchoWebserviceProvider project.

2. Install the certificate in the windows certificate cache

3. Setting up Audience Uri. In the WebConfig file, add the endpoint adresse to Audience Uris. 
   Not doing so, will give a security error when communicating with the service.

------------------------------------------------------------------------------------

Guidelines for building a new Webservice Provider:

Include the following libraries in your WCF project.
Microsoft.IdentityModel.
System.IdentityModel.
OIOSaml.Library

Most of the configuration is done in code, since the web.config doesnt allow all options.

1. In the web.config file add your ServiceCertificate. Add the service certificate to your trusted certificates, and grant the network service access.

2. Use a MessageContract to describe your service interface, instead of DataContracts. Insert the LibertyFrameworkHeader on request/response, look in MessageContracts.cs for example. This will display the header in the wdsl. 

3. On the service contract add [XmlSerializerFormat] attribute, it ensures correct serialization of the LibertyHeader.

4. On the service contract add the following fault contract to the operations:  [FaultContractAttribute(typeof(FrameworkFault), ProtectionLevel = ProtectionLevel.Sign)]
   This will describe the fault in the wsdl, as well as ensure that the fault is signed.

3. Use the ServiceProviderBinding.cs as binding. It upholds the standard and ensures interoperability with the Java implementation of OIOSaml. It can be configured for SSL.

4. In your <YourService>HostFactory call the following function as the last thing: OIOFederatedServiceCredentials.Setup(serviceHost)
   This adds support for Saml2SecurityTokens when using IssuedSecurityTokenParameters. 

5. In your Service, make sure to return LibertyFrameworkHeader and insert MessageId on response. Look in service.cs for example.

6. In the webconfig, you have the option to implement your own TrustedIssuerNameRegistry for validation of Certificates. The current one is a dummy implementation.

7. Remember to set Audience Uris up in the web.config. This should be the address of your service.

-------------------------------------------------------------------------------------

Observations:

1. When receiving other tokens but, saml1SecurityTokens, from the STS, they are received as GenericXmlSecurityToken. But on the service side, they are interpreted as saml2.

