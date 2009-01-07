using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Xml;
using EchoWebserviceProvider;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Samples.TrustClient;
using Microsoft.IdentityModel.Tokens.Saml2;
using NUnit.Framework;
using System.ServiceModel.Description;
using Microsoft.IdentityModel.SecurityTokenService;
using OIOSaml.Serviceprovider.Binding;
using OIOSaml.Serviceprovider.ClientFactories;
using OIOSaml.Serviceprovider.Headers;
using OIOSaml.Serviceprovider.Saml2GenevaFix;
using System.Xml.Serialization;

namespace Client
{
    [TestFixture]
    public class TestWSTrustClientInteroperability
    {
        X509Certificate2 clientCertifikat = CertificateUtil.GetCertificate("SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK", StoreLocation.LocalMachine, StoreName.My);

        X509Certificate2 serviceCertifikat = CertificateUtil.GetCertificate("SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK", StoreLocation.LocalMachine, StoreName.My);
        private const string DnsIdentityForServiceCertificates = "TDC TOTALLØSNINGER A/S - TDC Test";
             
        Uri STSAddress = new Uri("http://213.237.161.81:8082/sts/TokenService");

        [Test]
        public void GetSaml2SecurityTokenFromJavaSTS()
        {
            EndpointAddress endpointAddress = new EndpointAddress(STSAddress, EndpointIdentity.CreateDnsIdentity(DnsIdentityForServiceCertificates));
            WSTrustClient trustClient = STSClientFactory.GetWSTrustClient(clientCertifikat, serviceCertifikat, endpointAddress);

            SecurityToken bootstrapSecurityToken = MakeBootstrapSecurityToken();
            RequestSecurityToken rst = STSClientFactory.MakeRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, new Uri("http://localhost/Echo/service.svc/Echo"));

            GenericXmlSecurityToken token = (GenericXmlSecurityToken) trustClient.Issue(rst);
            trustClient.Close();

            Assert.IsTrue(token.InternalTokenReference.ToString().Contains("Saml2"));

            RequestEcho(token);
        }

        public void RequestEcho(SecurityToken token)
        {
            ChannelFactory<IEchoService2> echoServiceFactory = new ChannelFactory<IEchoService2>(new ServiceproviderBinding(), new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity(DnsIdentityForServiceCertificates)));

            echoServiceFactory.Credentials.ClientCertificate.Certificate = clientCertifikat;

            echoServiceFactory.Credentials.IssuedToken.LocalIssuerBinding = new SecurityTokenServiceBinding();
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerAddress = new EndpointAddress(new Uri("http://NotAnUrlAndNotToBeUsed"));
            echoServiceFactory.Credentials.ServiceCertificate.DefaultCertificate = serviceCertifikat;

            ExchangeClientCredentialsWithFederatedClientCredentials(echoServiceFactory);

            IEchoService2 echoService = echoServiceFactory.CreateChannelWithIssuedToken(token);
            ICommunicationObject channel = (ICommunicationObject)echoService;

            var req = new EchoMessage();
            req.structureToEcho = new Structure();
            req.Framework = new LibertyFrameworkHeader();
            var echoReply = echoService.Echo(req);

            channel.Close();

            Assert.IsNotNull(echoReply);
        }

        private void ExchangeClientCredentialsWithFederatedClientCredentials(ChannelFactory<IEchoService2> echoServiceFactory)
        {
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
        }


        private SecurityToken MakeBootstrapSecurityToken()
        {
            Saml2NameIdentifier identifier = new Saml2NameIdentifier("http://localhost/Echo");

            Saml2Assertion assertion = new Saml2Assertion(identifier);

            assertion.Issuer = new Saml2NameIdentifier("idp1.test.oio.dk");
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("Casper", new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")));
            Saml2Attribute atribute = new Saml2Attribute("dk:gov:saml:attribute:AssuranceLevel", "2");
            atribute.NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

            assertion.Statements.Add(new Saml2AttributeStatement(atribute));
            return new Saml2SecurityToken(assertion);
        }
    }
}
