OIOSAML IDWS Web Service Provider
------------------------------------------------------------------------------

This package contains the Web Service Provider POC. It consists of 3 services:

- ProviderService.echo - accepts a xml structure and sends it back to the 
  requestor. The service requires a SAML token from the STS.

- ProviderService.requestInteract - test R2I by checking if the user is known.
  If the user is not, a R2I reply is sent to the requestor, and the user is 
  redirected to the WSP and prompted for input.
  
- ProviderServiceSimple.echo - The same as ProviderService.echo, but without
  the security requirements.
  
  
Installation
------------------------------------------------------------------------------

This package requires GlassFish 2ur2+ to run. Furthermore, a couple of libraries
must be upgraded. Do this by downloading the latest version of Metro 2.0 and
install it in the GlassFish instance. Follow the installation instructions
in the downloaded archive.

If R2I is to be used, OIOSAML.java must be configured. If this application is 
run on the same machine as the poc-provider application, configure the home
configuration directory to something else than .oiosaml in
glassfish/domains/<domain>/config/domain.xml by inserting the following
in the <java-config> element: 

<jvm-options>-Doiosaml.home=/path/to/config/dir</jvm-options>


When requests are received, the certificate is checked against the GlassFish 
keystore. This means that you should import the STS certificate into 
glassfish/domains/<domain>/config/cacerts.jks with

keytool -import -trustcacerts -keystore cacerts.jks -file sts.keystore

Responses are signed with a key with alias voces. This key must be present
in  glassfish/domains/<domain>/config/keystore.jks

If you are using an exising pkcs12 certificate file, the following command can
be used to import it into the GlassFish keystore:
 
keytool -importkeystore -srckeystore fqdn.pfx -destkeystore keystore.jks -srcstoretype pkcs12 -srcalias 1 -destalias voces

All passwords to GlassFish keystores default to 'changeit'.


Deploy the war file and configure OIOSAML.java as usual. Refer to the 
OIOSAML.java documentation for how to do this.

