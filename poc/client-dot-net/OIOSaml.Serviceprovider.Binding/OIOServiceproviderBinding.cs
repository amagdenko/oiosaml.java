using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Text;

namespace OIOSaml.Serviceprovider.Binding
{
    public class OIOServiceproviderBinding : CustomBinding
    {
        public OIOServiceproviderBinding()
            : base(CreateBinding())
        {
        }

        private static System.ServiceModel.Channels.Binding CreateBinding()
        {
            TextMessageEncodingBindingElement encodingBindingElement = new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8);
            HttpTransportBindingElement httpTransport = new HttpTransportBindingElement();

            var messageSecurity = new AsymmetricSecurityBindingElement();
            messageSecurity.MessageSecurityVersion =
                MessageSecurityVersion.
                    WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;

            messageSecurity.InitiatorTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.Never);
            messageSecurity.InitiatorTokenParameters.RequireDerivedKeys = false;

            messageSecurity.RecipientTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.Never);
            messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;

            var tokenParam = new IssuedSecurityTokenParameters("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
            tokenParam.RequireDerivedKeys = false;
            tokenParam.KeyType = SecurityKeyType.AsymmetricKey;
            tokenParam.InclusionMode = SecurityTokenInclusionMode.AlwaysToRecipient;

            messageSecurity.EndpointSupportingTokenParameters.SignedEndorsing.Add(tokenParam);

            var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, httpTransport);

            return customBinding;
        }
    }
}

