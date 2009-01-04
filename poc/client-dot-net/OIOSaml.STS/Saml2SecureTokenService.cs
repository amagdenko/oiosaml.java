using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Samples.TrustClient;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace GenevaSTS
{
    public class Saml2SecureTokenService : SecurityTokenService
    {
        public const string ExpectedAddress = "http://localhost:8080/CalcService";
        
        public static X509Certificate2 RPCert = CertificateUtil.GetCertificate( "CN=localhost", StoreLocation.LocalMachine, StoreName.My );

        public Saml2SecureTokenService(SecurityTokenServiceConfiguration config)
            : base( config )
        {
            
        }
        
        protected override Scope GetScope( IClaimsPrincipal principal, RequestSecurityToken request )
        {
            Scope scope = new Scope( request );
            scope.SigningCredentials = this.SecurityTokenServiceConfiguration.SigningCredentials;
            scope.EncryptingCredentials = new X509EncryptingCredentials( RPCert );
            
            return scope;
        }

        protected override SecurityTokenDescriptor CreateSecurityTokenDescriptor(Scope scope)
        {
            SecurityTokenDescriptor td = base.CreateSecurityTokenDescriptor(scope);
            td.EncryptingCredentials = null;
            return td;   

        }

        protected override IClaimsIdentity GetOutputClaimsIdentity( IClaimsPrincipal principal, RequestSecurityToken request, Scope scope )
        {
            var issuedClaims = new List<Claim>() {
                new Claim( System.IdentityModel.Claims.ClaimTypes.Name, "Bob" ), 
            };
            
            return new ClaimsIdentity(issuedClaims);
        }
    }
}
