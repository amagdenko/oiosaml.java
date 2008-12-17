using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace EchoWebserviceProvider
{
    public class Saml2InitiatorFederatedServiceCredentials : FederatedServiceCredentials
    {
        protected Saml2InitiatorFederatedServiceCredentials(Saml2InitiatorFederatedServiceCredentials other)
            : base(other)
        {
        }

        public Saml2InitiatorFederatedServiceCredentials(ServiceCredentials credentials)
            : base(credentials)
        {
            var tokenhandler = (Saml2SecurityTokenHandler)this.SecurityTokenHandlers[typeof(Saml2SecurityToken)];
            tokenhandler.SamlSecurityTokenRequirement.IssuerNameRegistry = new TrustedIssuerNameRegistry();
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new Saml2InitiatorFederatedSecurityTokenManger(this);
        }

        protected override ServiceCredentials CloneCore()
        {
            return new Saml2InitiatorFederatedServiceCredentials(this);
        }

    }

   

}