using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Bindings.Bindings;
using Bindings.TokenClient;
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
            var audience = new Uri("https://172.16.232.1:8181/poc-provider/ProviderService");
            return GetIssuedToken(audience);
        }

        public static SecurityToken GetIssuedToken(Uri audience) 
        {
            var certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);
            var certificate2Service = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameSTS);
            var ep = new Uri("http://localhost:8080/sts/TokenService");
            return TokenClient.GetIssuedToken(audience, certificate2Client, certificate2Service, ep, MakeBootstrapSecurityToken());

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


    }
}
