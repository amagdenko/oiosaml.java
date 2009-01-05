using System.IdentityModel.Selectors;
using Microsoft.IdentityModel.Tokens;
using OIOSaml.Serviceprovider.Saml2GenevaFix;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class OIOFederatedSecurityTokenManger : FederatedSecurityTokenManager
    {
        public OIOFederatedSecurityTokenManger(OIOFederatedServiceCredentials credentials)
            : base(credentials,credentials.SecurityTokenHandlers, credentials.ClaimsAuthenticationManager, credentials.SaveBootstrapTokenInSession)
        {
        }

        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            var securityTokenSerializer = base.CreateSecurityTokenSerializer(version);


            return new Saml2InitiatorSecurityTokenSerializer(securityTokenSerializer);
        }
    }
}