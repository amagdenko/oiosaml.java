using System;
using System.IdentityModel.Tokens;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using EchoWebserviceProvider;
using EchoWebserviceprovider.Interfaces;
using Microsoft.IdentityModel.Samples.TrustClient;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens.Saml2;
using NUnit.Framework;
using OIOSaml.Serviceprovider.ClientFactories;
using OIOSaml.Serviceprovider.Headers;
using System.Net;
using System.ServiceModel.Security;

namespace Client
{
    [TestFixture]
    public class TestWebserviceProvider
    {
        TestWSTrustClientInteroperability STSConnection;

       [TestFixtureSetUp]
        public void TestFixtureSetUp()
       {
           //Test in the following class needs to run before this testfixture works,
           //Because i need a GenerixXmlSecurityToken, and i havent found a way to serialize/deserialize them properly yet.
           STSConnection = new TestWSTrustClientInteroperability();
       }

        X509Certificate2 clientCertifikat = CertificateUtil.GetCertificate("SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK", StoreLocation.LocalMachine, StoreName.My);

        X509Certificate2 serviceCertifikat = CertificateUtil.GetCertificate("SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK", StoreLocation.LocalMachine, StoreName.My);
        private const string DnsIdentityForServiceCertificates = "TDC TOTALLØSNINGER A/S - TDC Test";

        [Test]
        public void CommunicationWithWebserviceProvider()
        {
            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("http://localhost/Echo/service.svc/Echo");

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);
            
            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity(DnsIdentityForServiceCertificates)));
            ICommunicationObject channel = (ICommunicationObject)echoService;

            var req = new echo();
            req.structureToEcho = new Structure();
            req.Framework = new LibertyFrameworkHeader();
            var echoReply = echoService.Echo(req);

            channel.Close();

            Assert.IsNotNull(echoReply);
        }

        /// <summary>
        /// Fails because the audience is not present in the webconfig for the EchoWebserviceProvider.
        /// </summary>
        [Test, ExpectedException(typeof(MessageSecurityException))]
        public void WebserviceproviderReceivesWrongAudience()
        {
            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("http://NotValidEndPoint/Echo");//Failure

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);

            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity(DnsIdentityForServiceCertificates)));

            var req = new echo();
            req.structureToEcho = new Structure();
            req.Framework = new LibertyFrameworkHeader();
            
            echoService.Echo(req);
        }

        /// <summary>
        /// LibertyHeader is a Must
        /// </summary>
        [Test, ExpectedException(typeof(FaultException<FrameworkFault>))]
        public void MissingLibertyHeader()
        {
            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("http://localhost/Echo/service.svc/Echo");

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);

            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity(DnsIdentityForServiceCertificates)));

            var req = new echo();
            req.structureToEcho = new Structure();
            req.Framework = null; //Failure

            echoService.Echo(req);
        }

        /// <summary>
        /// LibertyHeader profile is a Must
        /// </summary>
        [Test, ExpectedException(typeof(FaultException<FrameworkFault>))]
        public void WrongProfileForLibertyHeader()
        {
            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("http://localhost/Echo/service.svc/Echo");

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);

            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity(DnsIdentityForServiceCertificates)));

            var req = new echo();
            req.structureToEcho = new Structure();
            req.Framework = new LibertyFrameworkHeader();
            req.Framework.Profile = "FailureToComply";//Failure

            echoService.Echo(req);
        }

        [Test]
        public void DotNetServiceSSLConversation()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate {return (true);};

            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("http://localhost/Echo/service.svc/Echo");

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);

            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("https://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo")));

            var req = new echo();
            req.structureToEcho = new Structure();
            req.Framework = new LibertyFrameworkHeader();

            var reply = echoService.Echo(req);
            Assert.IsNotNull(reply.Framework);
        }

        [Test]
        public void JAVAServiceSSLConversation()
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return (true);};

            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("https://oiosaml.trifork.com:8082/poc-provider/GenevaProviderService");

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);

            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("https://oiosaml.trifork.com:8082/poc-provider/GenevaProviderService")));

            var req = new echo();
            req.structureToEcho = new Structure();
            req.structureToEcho.value = "kvlsjvsldk";
            req.Framework = new LibertyFrameworkHeader();

            var reply = echoService.Echo(req);
            Assert.IsNotNull(reply.Framework);
            Assert.IsNotNull(reply.structureToEcho.value);
        }

        [Test]
        public void JAVAServiceNoSSLConversation()
        {
            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            Uri audience = new Uri("http://jre-mac.trifork.com:8880/poc-provider/GenevaProviderService");

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, audience);

            var token = STSConnection.GetIssuedToken(rst);

            IEchoService2 echoService = WebserviceproviderChannelFactory.CreateChannelWithIssuedToken<IEchoService2>(token, clientCertifikat, serviceCertifikat, new EndpointAddress(new Uri("http://jre-mac.trifork.com:8880/poc-provider/GenevaProviderService")));

            var req = new echo();
            req.structureToEcho = new Structure();
            req.structureToEcho.value = "kvlsjvsldk";
            req.Framework = new LibertyFrameworkHeader();

            var reply = echoService.Echo(req);
            Assert.IsNotNull(reply.Framework);
            Assert.IsNotNull(reply.structureToEcho.value);
        }
    }
}
