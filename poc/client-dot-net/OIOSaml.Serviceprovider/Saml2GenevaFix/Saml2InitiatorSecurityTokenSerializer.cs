using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Xml;
using Microsoft.IdentityModel.Tokens.Saml2;
using OIOSaml.Serviceprovider.Saml2GenevaFix;

namespace OIOSaml.Serviceprovider.Saml2GenevaFix
{
    public class Saml2InitiatorSecurityTokenSerializer : SecurityTokenSerializer
    {
        private readonly SecurityTokenSerializer serializer;

        protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenResolver)
        {
            var token = (Saml2SecurityToken)serializer.ReadToken(reader, tokenResolver);
            return new Saml2InitiatorSecurityToken(token.Assertion, token.SecurityKeys, token.IssuerToken);
        }

        #region WrappedPassthroughMethods
        public Saml2InitiatorSecurityTokenSerializer(SecurityTokenSerializer serializer)
        {
            this.serializer = serializer;
        }

        protected override bool CanReadTokenCore(XmlReader reader)
        {
            return serializer.CanReadToken(reader);
        }

        protected override bool CanWriteTokenCore(SecurityToken token)
        {
            return serializer.CanWriteToken(token);
        }

        protected override bool CanReadKeyIdentifierCore(XmlReader reader)
        {
            return serializer.CanReadKeyIdentifier(reader);
        }

        protected override bool CanWriteKeyIdentifierCore(SecurityKeyIdentifier keyIdentifier)
        {
            return serializer.CanWriteKeyIdentifier(keyIdentifier);
        }

        protected override bool CanReadKeyIdentifierClauseCore(XmlReader reader)
        {
            return serializer.CanReadKeyIdentifierClause(reader);
        }

        protected override bool CanWriteKeyIdentifierClauseCore(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            return serializer.CanWriteKeyIdentifierClause(keyIdentifierClause);
        }


        protected override void WriteTokenCore(XmlWriter writer, SecurityToken token)
        {
            serializer.WriteToken(writer, token);
        }

        protected override SecurityKeyIdentifier ReadKeyIdentifierCore(XmlReader reader)
        {
            return serializer.ReadKeyIdentifier(reader);
        }

        protected override void WriteKeyIdentifierCore(XmlWriter writer, SecurityKeyIdentifier keyIdentifier)
        {
            serializer.WriteKeyIdentifier(writer, keyIdentifier);
        }

        protected override SecurityKeyIdentifierClause ReadKeyIdentifierClauseCore(XmlReader reader)
        {
            return serializer.ReadKeyIdentifierClause(reader);
        }

        protected override void WriteKeyIdentifierClauseCore(XmlWriter writer, SecurityKeyIdentifierClause keyIdentifierClause)
        {
            serializer.WriteKeyIdentifierClause(writer, keyIdentifierClause);
        }
        #endregion WrappedPassthroughMethods
    }
}