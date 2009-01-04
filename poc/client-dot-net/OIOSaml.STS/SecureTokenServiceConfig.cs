using System;
using System.Security.Cryptography.X509Certificates;
using GenevaSTS;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Samples.TrustClient;

/// <summary>
/// Summary description for SecurityTokenServiceConfiguration
/// </summary>
/// 

    public class SecureTokenServiceConfig : SecurityTokenServiceConfiguration
    {
        public const string issuerAddress = "http://lh-z3jyrnwtj9d7/OIOSamlSTS/Service.svc";

        public SecureTokenServiceConfig()
            : base(issuerAddress, new X509SigningCredentials(CertificateUtil.GetCertificate("CN=localhost", StoreLocation.LocalMachine, StoreName.My)))
        {
            this.DefaultTokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            this.DefaultTokenLifetime = new TimeSpan(1, 0, 0, 0);
            SecurityTokenService = typeof(Saml2SecureTokenService);
            
        }
    }
