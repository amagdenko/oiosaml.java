using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class OIOSaml2SecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public OIOSaml2SecurityToken ReadOIOSaml2SecurityToken(XmlReader reader)
        {
            Saml2Assertion assertion = this.ReadAssertion(reader);
            ReadOnlyCollection<SecurityKey> keys = this.ResolveSecurityKeys(assertion, this.SamlSecurityTokenRequirement.ServiceTokenResolver);
            return new OIOSaml2SecurityToken(assertion, keys, this.ResolveIssuerToken(assertion, this.SamlSecurityTokenRequirement.IssuerTokenResolver));

        }

        internal ReadOnlyCollection<SecurityKey> ResolveSecurityKeys(Saml2Assertion assertion, SecurityTokenResolver resolver)
        {
          
            Saml2Subject subject = assertion.Subject;
          
            Saml2SubjectConfirmation confirmation = subject.SubjectConfirmations[0];
            if (confirmation.SubjectConfirmationData != null)
            {
                this.ValidateConfirmationData(confirmation.SubjectConfirmationData);
            }
            
            List<SecurityKey> list = new List<SecurityKey>();
            foreach (SecurityKeyIdentifier identifier in confirmation.SubjectConfirmationData.KeyIdentifiers)
            {
                SecurityKey key = null;
                foreach (SecurityKeyIdentifierClause clause in identifier)
                {
                    if ((resolver != null) && resolver.TryResolveSecurityKey(clause, out key))
                    {
                        list.Add(key);
                        break;
                    }
                }
                if (key == null)
                {
                    if (identifier.CanCreateKey)
                    {
                        key = identifier.CreateKey();
                        list.Add(key);
                        continue;
                    }
                    list.Add(new SecurityKeyElement(identifier, resolver));
                }
            }
            return list.AsReadOnly();
        }


    }
}
