using System;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class OIOFederatedServiceCredentials : FederatedServiceCredentials
    {
 
        public OIOFederatedServiceCredentials(ServiceCredentials credentials)
            : base(credentials)
        {

            this.ClaimsAuthenticationManager = ((FederatedServiceCredentials) credentials).ClaimsAuthenticationManager;
            var tokenhandler = (Saml2SecurityTokenHandler)this.SecurityTokenHandlers[typeof(Saml2SecurityToken)];
            tokenhandler.SamlSecurityTokenRequirement = ((Saml2SecurityTokenHandler)((FederatedServiceCredentials)credentials).SecurityTokenHandlers[typeof(Saml2SecurityToken)]).SamlSecurityTokenRequirement;
            tokenhandler.SamlSecurityTokenRequirement.AudienceUriMode = AudienceUriMode.Always;
            
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new OIOFederatedSecurityTokenManger(this);
        }

        protected override ServiceCredentials CloneCore()
        {
            return new OIOFederatedServiceCredentials(this);
        }

    }
}