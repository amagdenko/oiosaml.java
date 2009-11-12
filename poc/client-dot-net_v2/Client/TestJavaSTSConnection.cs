using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Bindings.Bindings;
using System.ServiceModel;
using System.Net.Security;
using System.ServiceModel.Security;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Client
{
    [TestFixture]
    public class TestJavaSTSConnection
    {
        static readonly string SigningCertificateNameSTS = @"CN=DANID A/S - DanID Test + SERIALNUMBER=CVR:30808460-UID:1237552804997, O=DANID A/S // CVR:30808460, C=DK";
        static readonly string SigningCertificateNameClient = @"CN=Allan Apoteker + SERIALNUMBER=CVR:25520041-RID:1237281362460, O=TRIFORK SERVICES A/S // CVR:25520041, C=DK";


        [Test]
        public void TestCommunication()
        {
            var issuedToken = GetIssuedToken();
            Assert.IsNotNull(issuedToken);
        }


        public static SecurityToken GetIssuedToken()
        {
            var audience = new Uri("https://172.30.161.162:8181/poc-provider/ProviderService");
            return GetIssuedToken(audience);

        }


        public static SecurityToken GetIssuedToken(Uri audience)
        {
            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);
            X509Certificate2 certificate2Service = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameSTS);

            WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(SecureTokenServiceBindings.GetIssuedTokenBindingNonSSL(), new EndpointAddress(new Uri(@"http://localhost:8080/sts/TokenService"), EndpointIdentity.CreateDnsIdentity("DANID A/S - DanID Test")));
            trustChannelFactory.Credentials.ServiceCertificate.DefaultCertificate = certificate2Service;
            trustChannelFactory.Credentials.ClientCertificate.Certificate = certificate2Client;
            trustChannelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            trustChannelFactory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

            trustChannelFactory.TrustVersion = TrustVersion.WSTrust13;
            var channel = (WSTrustChannel)trustChannelFactory.CreateChannel();
            var bootstrapSecurityToken = MakeBootstrapSecurityToken();
            var rst = MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, certificate2Client, audience, new List<RequestClaim>());
            var response = channel.Issue(rst);
            return response;

        }

        public static SecurityToken MakeBootstrapSecurityToken()
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

        public static RequestSecurityToken MakeOnBehalfOfSTSRequestSecurityToken(SecurityToken bootstrapSecurityToken, X509Certificate2 clientCertificate, Uri RelyingPartyAdress, IEnumerable<RequestClaim> requestClaims)
        {
            var requestSecurityToken = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);
            Uri ServiceAddress = RelyingPartyAdress;
            requestSecurityToken.AppliesTo = new EndpointAddress(ServiceAddress);
            requestSecurityToken.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            requestSecurityToken.KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            requestSecurityToken.OnBehalfOf = new SecurityTokenElement(bootstrapSecurityToken);
            SecurityKeyIdentifierClause clause = new X509RawDataKeyIdentifierClause(clientCertificate);
            requestSecurityToken.UseKey = new UseKey(new SecurityKeyIdentifier(clause), new X509SecurityToken(clientCertificate));

            foreach (RequestClaim claim in requestClaims)
            {
                requestSecurityToken.Claims.Add(claim);
            }

            return requestSecurityToken;
        }

    }
}
