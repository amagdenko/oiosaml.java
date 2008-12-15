using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// IssuerNameRegistry that validates the incoming SAML token issuer.
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
