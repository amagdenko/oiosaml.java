using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using Client.Test;
using EchoWebserviceProvider;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Samples.TrustClient;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens.Saml2;
using NUnit.Framework;
using OIOSaml.Serviceprovider.Binding;
using OIOSaml.Serviceprovider.Saml2GenevaFix;
using System.IdentityModel.Tokens;

namespace Client
{
    [TestFixture]
    public class TestEchoWebserviceprovider
    {
        X509Certificate2 clientCertifikat = CertificateUtil.GetCertificate("CN=localhost", StoreLocation.LocalMachine, StoreName.My);

        [TestFixtureSetUp]
        public void FixtureSetup()
        {
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(
                delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
                    {
                        return (true);
                    });
        }

        [Test]
        public void RequestEcho()
        {
            ChannelFactory<IEchoService> echoServiceFactory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(), new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity("TDC TOTALLØSNINGER A/S - TDC Test")));

            echoServiceFactory.Credentials.ClientCertificate.Certificate = CertificateUtil.GetCertificate("CN=localhost",
                                                                                              StoreLocation.LocalMachine,
                                                                                              StoreName.My);
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerBinding = new SecurityTokenServiceBinding();
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerAddress = new EndpointAddress(new Uri("http://213.237.161.81:8082/sts/TokenService"), new DnsEndpointIdentity("TDC TOTALLØSNINGER A/S - TDC Test"));
            echoServiceFactory.Credentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.Root, X509FindType.FindBySerialNumber, "40 36 ac 11");// = CertificateUtil.GetCertificate("CN=STS", StoreLocation.LocalMachine, StoreName.My);

            ClientCredentials other = echoServiceFactory.Endpoint.Behaviors.Find<ClientCredentials>();
            if (other != null)
            {
                echoServiceFactory.Endpoint.Behaviors.Remove(other.GetType());
            }
            FederatedClientCredentials item = null;
            if (other != null)
            {
                item = new OIOFederatedClientCredentials(other);
            }
            echoServiceFactory.Endpoint.Behaviors.Add(item);


            ICommunicationObject channel = null;

            //var saml2Token = null;// new TestService().ServiceIsUp();
           
            //IEchoService echoService = echoServiceFactory.CreateChannelWithIssuedToken(saml2Token);
            //channel = (ICommunicationObject)echoService;
            //var echoReply = echoService.Echo(new Structure());

            //channel.Close();

            //Assert.IsNotNull(echoReply);
        }
    }
}
