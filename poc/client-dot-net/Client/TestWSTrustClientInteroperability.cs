using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Xml;
using EchoWebserviceProvider;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Samples.TrustClient;
using NUnit.Framework;
using System.ServiceModel.Description;
using Microsoft.IdentityModel.SecurityTokenService;
using OIOSaml.Serviceprovider.Binding;
using OIOSaml.Serviceprovider.Saml2GenevaFix;

namespace Client
{
    [TestFixture]
    public class TestWSTrustClientInteroperability
    {
        X509Certificate2 clientCertifikat = CertificateUtil.GetCertificate("CN=localhost", StoreLocation.LocalMachine, StoreName.My);

        X509Certificate2 securityTokenServiceCertifikat =
            CertificateUtil.GetCertificate(
                "SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK",
                StoreLocation.LocalMachine, StoreName.My);


        [Test]
        public void RequestToken()
        {
            Uri STSAddress = new Uri("http://213.237.161.81:8082/sts/TokenService");
            
            var clientCredentials = new ClientCredentials();
            clientCredentials.ClientCertificate.Certificate = clientCertifikat;

            WSTrustClient trustClient = new WSTrustClient(new SecurityTokenServiceBinding(), new EndpointAddress(STSAddress, EndpointIdentity.CreateDnsIdentity("TDC TOTALLØSNINGER A/S - TDC Test")), TrustVersion.WSTrust13, clientCredentials);
            trustClient.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
            trustClient.ClientCredentials.ServiceCertificate.DefaultCertificate = securityTokenServiceCertifikat;
            trustClient.SecurityTokenHandlers.Clear();
            
            RequestSecurityToken rst = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);
            Uri ServiceAddress = new Uri("http://localhost/Echo/service.svc/Echo");
            rst.AppliesTo = new EndpointAddress(ServiceAddress);
            rst.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            rst.KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";

            SecurityKeyIdentifierClause clause = new X509RawDataKeyIdentifierClause(clientCertifikat);
            rst.UseKey = new UseKey(new SecurityKeyIdentifier(clause), new X509SecurityToken(clientCertifikat));

            GenericXmlSecurityToken token = (GenericXmlSecurityToken) trustClient.Issue(rst);

            OIOSaml2SecurityTokenHandler handler = new OIOSaml2SecurityTokenHandler();

            XmlReader reader = GetAssertionReader(token.TokenXml);

            //XmlDocument doc = new XmlDocument();
            //doc.Load(reader);
            //doc.Save(@"c:\logs\assertion.xml");

            var token2 = handler.ReadOIOSaml2SecurityToken(reader);
            var token3 = new OIOSaml2SecurityToken(token2.Assertion, token2.SecurityKeys, token2.IssuerToken);
            Assert.IsNotNull(token);

            

            RequestEcho(token2);
        }

        public void RequestEcho(SecurityToken token)
        {
            ChannelFactory<IEchoService> echoServiceFactory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(), new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/EchoWebserviceProvider/service.svc/Echo"), new DnsEndpointIdentity("TDC TOTALLØSNINGER A/S - TDC Test")));

            echoServiceFactory.Credentials.ClientCertificate.Certificate = CertificateUtil.GetCertificate("CN=localhost",
                                                                                              StoreLocation.LocalMachine,
                                                                                              StoreName.My);
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerBinding = new SecurityTokenServiceBinding();
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerAddress = new EndpointAddress(new Uri("http://213.237.161.81:8082/sts/TokenService"), new DnsEndpointIdentity("TDC TOTALLØSNINGER A/S - TDC Test"));
            echoServiceFactory.Credentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.Root, X509FindType.FindBySerialNumber, "40 36 ac 11");// = CertificateUtil.GetCertificate("CN=STS", StoreLocation.LocalMachine, StoreName.My);
            CertificateUtil.GetCertificate("CN=localhost", StoreLocation.LocalMachine, StoreName.My);

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

            // Creates a channel that will use the provided issued token to
            // secure the messages sent to the calculator service.
            // Note that the configuration of this channel factory is identical 
            // to the "fully automated" scenario except for the use of this
            // extension method to create the actual channel.
            //
            IEchoService echoService = echoServiceFactory.CreateChannelWithIssuedToken(token);
            channel = (ICommunicationObject)echoService;
            var echoReply = echoService.Echo(new Structure());
            
            channel.Close();

            Assert.IsNotNull(echoReply);
        }

        public XmlReader GetAssertionReader(XmlElement assertElement)
        {
            byte[] byteArray = GetAsByteArray(assertElement.OuterXml);


            MemoryStream memoryStream = GetAsMemoryStream(byteArray);


            return XmlReader.Create(memoryStream);
        }

        private byte[] GetAsByteArray(string text)
        {
            byte[] byteArray = new byte[text.Length];
            var encoding = new System.Text.UTF8Encoding();
            byteArray = encoding.GetBytes(text);
            return byteArray;
        }

        public MemoryStream GetAsMemoryStream(byte[] byteArray)
        {
            // Load the memory stream
            MemoryStream memoryStream = new MemoryStream(byteArray);
            memoryStream.Seek(0, SeekOrigin.Begin);
            memoryStream.Position = 0;
            return memoryStream;
        }
    }
}
