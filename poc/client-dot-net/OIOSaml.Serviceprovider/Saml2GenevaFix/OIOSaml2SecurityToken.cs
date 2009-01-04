using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class OIOSaml2SecurityToken : Saml2SecurityToken
    {
        public override T CreateKeyIdentifierClause<T>()
        {
            return new SamlAssertionKeyIdentifierClause(this.Assertion.Id.Value) as T;
        }

        #region Constructors

        public OIOSaml2SecurityToken(Saml2Assertion assertion)
            : base(assertion)
        {
        }

        public OIOSaml2SecurityToken(Saml2Assertion assertion, ReadOnlyCollection<SecurityKey> keys, SecurityToken issuerToken)
            : base(assertion, keys, issuerToken)
        {
        }

        #endregion Constructors

    }
}