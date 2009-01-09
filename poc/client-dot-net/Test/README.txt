OIOSAML Test
-----------------------------------------------------------------------------------

The testcases included in this assembly checks for:
1. Compliance/Interoperability between Java and .Net service providers.
2. Proper responses from a service provider in various fault scenerios.
3. Communication between Java POC STS and .Net WSTrustClient.

-----------------------------------------------------------------------------------

Prerequesits:

Geneva Framework Beta
Vista or Windows Server 2008 OS
Nunit 2.4.8

-----------------------------------------------------------------------------------

Getting the Tests up and running:

For the tests to work it needs a SecureTokenService that issues valid Saml2SecurityTokens.
For this there is an up and running Proof of Concept STS hosted by ITST. Or you can host your own
Java STS for test purposes. The sourcecode for it, can be located at the following Url:
https://svn.softwareborsen.dk/oiosaml.java/poc/sts/

-----------------------------------------------------------------------------------

