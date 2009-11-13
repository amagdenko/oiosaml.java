Client
-----------------------------------------------------------------------------------

Test implementation with focus on the communication between Java and .Net, as to whether they comply to the standard and is interoperable.
Is based on private DLL's issued from Microsoft(System.servicemodel.dll, System.identitymodel.dll, Microsoft.identitymodel.dll)

-----------------------------------------------------------------------------------

Contents:

TestJavaConnection	Talks to Java STS.
TestWebserviceProvider	Talks to a Java Webserviceprovider and a Geneva .Net provider.	

-----------------------------------------------------------------------------------

To run the tests, install the Java STS.

Install the certificates in the certificate cache.

The Geneva Webserviceprovider is a selfcontained service, so it can be started, and then run the NUnit Tests in the Client Project against it.

For setting up the Java Webservice STS and Service provider, that is described elsewhere.
