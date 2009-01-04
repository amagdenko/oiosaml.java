using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel.Description;
using System.Text;
using Microsoft.IdentityModel.Protocols.WSTrust;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class OIOFederatedClientCredentials : FederatedClientCredentials
    {
        public OIOFederatedClientCredentials(ClientCredentials other):base(other)
        {
        }

        public override System.IdentityModel.Selectors.SecurityTokenManager CreateSecurityTokenManager()
        {
            return new OIOFederatedClientCredentialsTokenManager(this);
        }

        protected override ClientCredentials CloneCore()
        {
            return new OIOFederatedClientCredentials(this);
        }
    }
}
