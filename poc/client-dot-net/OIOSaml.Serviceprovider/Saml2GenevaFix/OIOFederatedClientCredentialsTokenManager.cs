using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Protocols.WSTrust;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class OIOFederatedClientCredentialsTokenManager : FederatedClientCredentialsSecurityTokenManager
    {
        public OIOFederatedClientCredentialsTokenManager(OIOFederatedClientCredentials credentials)
            : base(credentials)
        {
        }

        public override System.IdentityModel.Selectors.SecurityTokenSerializer CreateSecurityTokenSerializer(System.IdentityModel.Selectors.SecurityTokenVersion version)
        {
            var securityTokenSerializer = base.CreateSecurityTokenSerializer(version);


            return new Saml2InitiatorSecurityTokenSerializer(securityTokenSerializer);
        }

        public override System.IdentityModel.Selectors.SecurityTokenProvider CreateSecurityTokenProvider(System.IdentityModel.Selectors.SecurityTokenRequirement tokenRequirement)
        {
            return base.CreateSecurityTokenProvider(tokenRequirement);
        }

        public override System.IdentityModel.Selectors.SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(System.IdentityModel.Selectors.SecurityTokenRequirement tokenRequirement, out System.IdentityModel.Selectors.SecurityTokenResolver outOfBandTokenResolver)
        {
            return base.CreateSecurityTokenAuthenticator(tokenRequirement, out outOfBandTokenResolver);
        }
    }
}
