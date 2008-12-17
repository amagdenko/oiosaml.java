using System.IdentityModel.Selectors;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using OIOSaml.Serviceprovider.Binding;
using OIOSaml.Serviceprovider.Saml2GenevaFix;

namespace EchoWebserviceProvider
{
    public class Saml2InitiatorFederatedSecurityTokenManger : FederatedSecurityTokenManager
    {
        public Saml2InitiatorFederatedSecurityTokenManger(Saml2InitiatorFederatedServiceCredentials credentials)
            : base(credentials)
        {
        }
       
        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            var securityTokenSerializer = base.CreateSecurityTokenSerializer(version);

            return new Saml2InitiatorSecurityTokenSerializer(securityTokenSerializer);
        }
    }
}