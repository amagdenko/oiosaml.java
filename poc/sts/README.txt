OIOSAML Trust Demo STS
----------------------------------------------------

This package contains the OIOSAML Trust Demo STS. This is a WS-Trust 1.3 
compliant STS, which can issue tokens according to the OIO-Trust profile. 
The server is in no way production ready, and has these limitations:

- Only supports WS-Trust 1.3
- Supports both SOAP 1.1 and 1.2
- Only supports SAML 2.0 TokenType
- All SAML Assertion attributes are copied from the request assertion
- Requests must contain a SAML Assertion in OnBehalfOf
- Requests must be signed
- There is no real error handling
- The AppliesTo value will be copied without further checking

The package uses OIOSAML.java and OIOSAML-Trust for basic SAML and 
WS-Trust support.


Configuration
----------------------------------------------------

The application expects a .oiosaml dir in user.home. This will be created 
automatically on the first startup if does not exist. In this directory, a file
named "sts.properties" must be created and have three settings:

sts.certificate.location=sts.keystore
sts.certificate.password=Test1234
sts.entityId=http://jre-mac.trifork.com/sts

The keystore.location property points to the keystore containing the STS' 
private key. The location is relative to .oiosaml. The keystore should contain
only one private key.

entityId configures the STS entity id. This is the value which will be inserted
into the Issuer field of the generated assertion.


Installation
----------------------------------------------------

Simply deploy sts.war to a servlet container such as Tomcat or GlassFish.

When the application is deployed, a WSDL file is available at
/sts/wsdl

The STS service itself is available at
/sts/TokenService

Depending on which JDK the system is running on, it might be necessary to
endorse a new Xerces library. If the application fails on startup with JAXP
errors, copy the jar files in endorsed/ to the servlet container's endorsed
dir. Where this is depends on the container, so consult the documentation.


Source code
----------------------------------------------------

Source code for the STS is available at https://svn.softwareborsen.dk/oiosaml.java/poc/sts

The code is licensed under Mozilla Public License 1.1
