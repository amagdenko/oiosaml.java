using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Security.Cryptography.X509Certificates;
using Bindings.TokenClient;

namespace WPFClient
{
    public class TokenUtil
    {
        static readonly string SigningCertificateNameSTS = @"CN=DANID A/S - DanID Test + SERIALNUMBER=CVR:30808460-UID:1237552804997, O=DANID A/S // CVR:30808460, C=DK";
        static readonly string SigningCertificateNameClient = @"CN=Allan Apoteker + SERIALNUMBER=CVR:25520041-RID:1237281362460, O=TRIFORK SERVICES A/S // CVR:25520041, C=DK";

        public static SecurityToken MakeBootstrapSecurityToken()
        {
            Saml2NameIdentifier identifier = new Saml2NameIdentifier("http://localhost/Echo");

            Saml2Assertion assertion = new Saml2Assertion(identifier);

            assertion.Issuer = new Saml2NameIdentifier("idp1.test.oio.dk");
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("Test", new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")));
            Saml2Attribute atribute = new Saml2Attribute("dk:gov:saml:attribute:AssuranceLevel", "2");
            atribute.NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

            assertion.Statements.Add(new Saml2AttributeStatement(atribute));
            return new Saml2SecurityToken(assertion);
        }

        public static SecurityToken GetIssuedToken(string STSUrl, string audience)
        {
            var certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);
            var certificate2Service = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameSTS);
            return TokenClient.GetIssuedToken(new Uri(audience), certificate2Client, certificate2Service, new Uri(STSUrl), MakeBootstrapSecurityToken());
        }
    }
}
