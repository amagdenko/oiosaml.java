﻿using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Dummy implementation, not to be used in production. Is needed for federated services.
/// </summary>
    public class TrustedIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
            X509SecurityToken x509Token = securityToken as X509SecurityToken;
            if (x509Token != null)
            {
                return x509Token.Certificate.SubjectName.Name;
            }

            throw new SecurityTokenException("Untrusted issuer.");
        }
    }
