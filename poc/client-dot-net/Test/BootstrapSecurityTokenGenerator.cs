using System;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Client
{
    public class BootstrapSecurityTokenGenerator
    {
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
