OIOSAML IDWS Web Service Consumer
------------------------------------------------------------------------------

This contains the Web Service Consumer POC. The WSC is a SAML 2.0 Service 
Provider which sends a request to a web service after retrieving a token from
an STS.


Installation
------------------------------------------------------------------------------

The WSC is based on OIOSAML.java. After deploying the war file to a servlet 
container, OIOSAML.java must be configured. Refer to the OIOSAML.java
documentation for how to do this.

When OIOSAML.java is configured, some properties must be added to 
oiosaml-sp.properties:

# url to the poc-provider service 
poc.provider=http://poc-provider_url

# keystore containing the sts certificate, relative to oiosaml-sp.properties
oiosaml-trust.certificate.location=certificate/TestVOCES1.pfx

# password for the sts keystore 
oiosaml-trust.certificate.password=Test1234

# certificate alias in the sts keystore
oiosaml-trust.certificate.alias=tdc totalløsninger a/s - tdc test


When the application is configured, access it using a browser. There are three
options available:

- Click on "Page requiring login" to test the SAML 2.0 SP
- Click on "Trigger Request to Interact" to test R2I
- Click on "Trigger token request" to make a request to the STS. When the 
  request has been made, click on the link at the bottom of the page to send
  the actual Web service request with the token.
  

To make token requests work, the SAML assertion must contain a Discovery EPR 
in the urn:liberty:disco:2006-08:DiscoveryEPR attribute. The value must be 
base64 encoded xml, and the assertion must be signed.

The STS endpoint address will also be extracted from the Discovery EPR.

