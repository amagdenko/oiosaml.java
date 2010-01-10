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

The Geneva Webserviceprovider is a webservice, run the NUnit Tests in the Client Project against it.

For installing the service in IIS 7, do the following.

1. Register ASPNET with IIS. Call this from a command prompt with admin rights: aspnet_regiis.exe -i
2. Configure WCF for IIS. In the windows feature enable, enable WCF for IIS.
3. Assosiate a certificate with https in IIS manager.

For setting up the Java Webservice STS and Service provider, that is described elsewhere.
