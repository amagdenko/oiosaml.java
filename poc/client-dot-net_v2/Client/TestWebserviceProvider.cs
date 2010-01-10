using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Bindings.ServiceInterfaces;
using System.ServiceModel;
using Bindings.Bindings;
using System.Net.Security;
using System.ServiceModel.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Bindings.Data;
using Bindings.CustomHeaders;
using System.IdentityModel.Tokens;
using Bindings.MessageContracts;
using System.Net;

namespace Client
{
    [TestFixture]
    public class TestWebserviceProvider
    {
//        static readonly string SigningCertificateNameGenevaService = @"CN=Allan Apoteker + SERIALNUMBER=CVR:25520041-RID:1237281362460, O=TRIFORK SERVICES A/S // CVR:25520041, C=DK";
        static readonly string SigningCertificateNameGenevaService = @"CN=STS";
        static readonly string SigningCertificateNameClient = @"SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK";
        static readonly string JavaWSPSSLCertificate = @"CN=recht-laptop, OU=Sun Java System Application Server, O=Sun Microsystems, L=Santa Clara, S=California, C=US";
        static readonly string SigningCertificateNameJavaService = @"SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK";

        [Test]
        public void TestGenevaWebserviceProvider()
        {
            X509Certificate2 sslCertJavaWSP = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, JavaWSPSSLCertificate);

            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

//            Uri uri = new Uri("http://localhost:6020/Echo");
            Uri uri = new Uri("http://csky-pc/test/Service1.svc");
            EndpointAddress address = new EndpointAddress(uri);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken();

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, "CN=STS");// SigningCertificateNameGenevaService);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
                Assert.AreEqual("Badabam", result.structureToEcho.value);
            }
        }

        [Test]
        public void TestGenevaWebserviceProvider_WithSSL()
        {
            X509Certificate2 sslCertJavaWSP = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, JavaWSPSSLCertificate);

            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

            //            Uri uri = new Uri("http://localhost:6020/Echo");
            Uri uri = new Uri("https://csky-pc/test/Service1.svc");
            EndpointAddress address = new EndpointAddress(uri);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken();

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(true), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, "CN=STS");// SigningCertificateNameGenevaService);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
                Assert.AreEqual("Badabam", result.structureToEcho.value);
            }
        }

        /// <summary>
        /// Fails because the audience is not present in the list of allowed audience in the EchoWebserviceProvider.
        /// </summary>
        [Test, ExpectedException]
        public void WebserviceproviderReceivesWrongAudience()
        {
            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

            Uri uri = new Uri("http://csky-pc/test/Service1.svc");
            
            EndpointAddress address = new EndpointAddress(uri);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken(new Uri("http://NotValidEndPoint/Echo"));

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameGenevaService);

                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
            }
        }

        /// <summary>
        /// LibertyHeader profile is a Must
        /// </summary>
        [Test, ExpectedException(typeof(FaultException<FrameworkFault>))]
        public void MissingLibertyHeader()
        {
            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

            Uri uri = new Uri("http://csky-pc/test/Service1.svc");
            
            EndpointAddress address = new EndpointAddress(uri);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken();

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameGenevaService);

                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = null;
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
            }
        }

        /// <summary>
        /// LibertyHeader profile is a Must
        /// </summary>
        [Test, ExpectedException(typeof(FaultException<FrameworkFault>))]
        public void WrongProfileForLibertyHeader()
        {
            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

            Uri uri = new Uri("http://csky-pc/test/Service1.svc");
            
            EndpointAddress address = new EndpointAddress(uri);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken();

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameGenevaService);

                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.Framework.Profile = "FailurToComply";
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
            }
        }

        [Test]
        public void TestJavaWebserviceProvider()
        {
            X509Certificate2 sslCertJavaWSP = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, JavaWSPSSLCertificate);

            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

            Uri uri = new Uri("http://172.16.232.1:8880/poc-provider/ProviderService");
            EndpointAddress address = new EndpointAddress(uri);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken(new Uri("http://172.16.232.1:8880/poc-provider/ProviderService"));

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameJavaService);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
                Assert.AreEqual("Badabam", result.structureToEcho.value);
            }
        }

        [Test]
        public void TestJavaWebserviceProviderWithSSL()
        {
            X509Certificate2 sslCertJavaWSP = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, JavaWSPSSLCertificate);

            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);

            Uri uri = new Uri("https://172.16.232.1:8181/poc-provider/ProviderService");
            EndpointIdentity identity = EndpointIdentity.CreateX509CertificateIdentity(sslCertJavaWSP);

            EndpointAddress address = new EndpointAddress(uri, identity);

            SecurityToken issuedToken = TestJavaSTSConnection.GetIssuedToken(new Uri("https://172.16.232.1:8181/poc-provider/ProviderService"));
            ServicePointManager.ServerCertificateValidationCallback = delegate
            {
                return (true);
            };//Removes Validationcheck of SSL certificate, should not be here for Production.

            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(true), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameJavaService);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;

                var result = service.Echo(echoRequest);
                Assert.AreEqual("Badabam", result.structureToEcho.value);
            }
        }
    }

}
