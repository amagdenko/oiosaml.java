using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.WSTrust;
using System.ServiceModel;
using Bindings.Bindings;
using System.ServiceModel.Security;
using System.Net.Security;
using Microsoft.IdentityModel.Tokens;

namespace Bindings.TokenClient
{
    /// <summary>
    /// Client for accessing a OIO-Trust compliant token service.
    /// 
    /// The GetIssuedToken method will request a token from the STS. It must be supplied with an audience (id of the provider
    /// which should receive the issued token), the client certifcate (and key), the sts certificate for validation,
    /// and a SecurityToken which is included in ActAs in the issue call.
    /// </summary>
    public class TokenClient
    {
        public static SecurityToken GetIssuedToken(Uri audience, X509Certificate2 clientCertificate, X509Certificate2 stsCertificate, Uri endpoint, SecurityToken bootstrapSecurityToken)
        {
            WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(SecureTokenServiceBindings.GetIssuedTokenBindingNonSSL(), new EndpointAddress(endpoint, EndpointIdentity.CreateDnsIdentity("DANID A/S - DanID Test")));
            trustChannelFactory.Credentials.ServiceCertificate.DefaultCertificate = stsCertificate;
            trustChannelFactory.Credentials.ClientCertificate.Certificate = clientCertificate;
            trustChannelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            trustChannelFactory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

            trustChannelFactory.TrustVersion = TrustVersion.WSTrust13;
            var channel = (WSTrustChannel)trustChannelFactory.CreateChannel();
            var rst = RequestSecurityToken(bootstrapSecurityToken, clientCertificate, audience, new List<RequestClaim>());
            var response = channel.Issue(rst);
            return response;

        }

        /// <summary>
        /// Build a new RequestSecurityToken structure without actually sending it.
        /// </summary>
        /// <param name="bootstrapSecurityToken">The token to include in ActAs</param>
        /// <param name="clientCertificate">The instance certificate. Must have a private key.</param>
        /// <param name="RelyingPartyAdress">Address/uri of the provider service which is going to receive the token in the end</param>
        /// <param name="requestClaims">Any additional claims to add to the request</param>
        /// <returns></returns>
        public static RequestSecurityToken RequestSecurityToken(SecurityToken bootstrapSecurityToken, X509Certificate2 clientCertificate, Uri RelyingPartyAdress, IEnumerable<RequestClaim> requestClaims)
        {
            var requestSecurityToken = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);
            requestSecurityToken.AppliesTo = new EndpointAddress(RelyingPartyAdress);
            requestSecurityToken.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            requestSecurityToken.KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            requestSecurityToken.ActAs = new SecurityTokenElement(bootstrapSecurityToken);
            SecurityKeyIdentifierClause clause = new X509RawDataKeyIdentifierClause(clientCertificate);
            requestSecurityToken.UseKey = new UseKey(new SecurityKeyIdentifier(clause), new X509SecurityToken(clientCertificate));

            foreach (RequestClaim claim in requestClaims)
            {
                requestSecurityToken.Claims.Add(claim);
            }

            return requestSecurityToken;
        }

    }
}
