using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using Microsoft.IdentityModel.SecurityTokenService;
using NUnit.Framework;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Samples.TrustClient;
using System.IdentityModel.Tokens;


namespace Client.Test
{
    [TestFixture]
    public class TestService
    {
        [TestFixtureSetUp]
        public void FixtureSetUp()
        {
            
        }



        /// <summary>
        /// fejler på grund af asymmetric key
        /// </summary>
        [Test]
        public void ServiceIsUp()
        {
            WSTrustClient trustClient = new WSTrustClient(GetSecurityTokenServiceBinding(), new EndpointAddress(new Uri("http://lh-z3jyrnwtj9d7/OIOSamlSTS/Service.svc")));
            trustClient.ClientCredentials.ClientCertificate.Certificate = CertificateUtil.GetCertificate("CN=localhost", StoreLocation.LocalMachine,
                                                                                                         StoreName.My);
            RequestSecurityToken rst = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);
            rst.AppliesTo = new EndpointAddress("http://localhost/Echo/service.svc/Echo");
            rst.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            rst.KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            SecurityKeyIdentifierClause clause = new X509RawDataKeyIdentifierClause(CertificateUtil.GetCertificate("CN=localhost",
                                                                                                                   StoreLocation.LocalMachine,
                                                                                                                   StoreName.My));

            rst.UseKey = new UseKey(new SecurityKeyIdentifier(clause), new X509SecurityToken(CertificateUtil.GetCertificate("CN=localhost",
                                                                                                                            StoreLocation.LocalMachine,
                                                                                                                            StoreName.My)));


            var securityToken = trustClient.Issue(rst);
            
            Assert.IsNotNull(securityToken);

        }

        private static Binding GetSecurityTokenServiceBinding()
        {
       
            WS2007HttpBinding binding = new WS2007HttpBinding();
            binding.Security.Message.EstablishSecurityContext = false;
            return binding;
        }
    }
}