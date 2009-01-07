using System;
using System.IdentityModel.Tokens;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;
using OIOSaml.Serviceprovider.Binding;

namespace OIOSaml.Serviceprovider.ClientFactories
{
    public class WSTrustClientFactory
    {
        public static WSTrustClient GetWSTrustClient(X509Certificate2 clientCertificate, X509Certificate2 securityTokenServiceCertificate, EndpointAddress endpointAddress)
        {
            var clientCredentials = new ClientCredentials();
            clientCredentials.ClientCertificate.Certificate = clientCertificate;


            WSTrustClient trustClient = new WSTrustClient(new SecurityTokenServiceBinding(), endpointAddress, TrustVersion.WSTrust13, clientCredentials);
            trustClient.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
            trustClient.ClientCredentials.ServiceCertificate.DefaultCertificate = securityTokenServiceCertificate;
            return trustClient;
        }

        public static RequestSecurityToken MakeOnBehalfOfSTSRequestSecurityToken(SecurityToken bootstrapSecurityToken, X509Certificate2 clientCertificate, Uri RelyingPartyAdress)
        {
            var requestSecurityToken = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);
            Uri ServiceAddress = RelyingPartyAdress;
            requestSecurityToken.AppliesTo = new EndpointAddress(ServiceAddress);
            requestSecurityToken.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            requestSecurityToken.KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            requestSecurityToken.OnBehalfOf = new SecurityTokenElement(bootstrapSecurityToken);
            SecurityKeyIdentifierClause clause = new X509RawDataKeyIdentifierClause(clientCertificate);
            requestSecurityToken.UseKey = new UseKey(new SecurityKeyIdentifier(clause), new X509SecurityToken(clientCertificate));
            return requestSecurityToken;
        }

        
    }
}
