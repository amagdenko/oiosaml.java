using System;
using System.IdentityModel.Selectors;
using System.ServiceModel;
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

        public static void Setup(ServiceHost serviceHost)
        {
            FederatedServiceCredentials.ConfigureServiceHost(serviceHost);

            var federatedCredentials = (FederatedServiceCredentials)serviceHost.Credentials;

            // Remove the default ServiceCredentials behavior.
            serviceHost.Description.Behaviors.Remove<ServiceCredentials>();

            serviceHost.Description.Behaviors.Add(new OIOFederatedServiceCredentials(federatedCredentials));
        }

    }
}