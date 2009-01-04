using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Text;

namespace OIOSaml.Serviceprovider.Binding
{
    public class SecurityTokenServiceBinding : CustomBinding
    {
        public SecurityTokenServiceBinding()
            : base(CreateBinding())
        {
        }

        private static System.ServiceModel.Channels.Binding CreateBinding()
        {
            TextMessageEncodingBindingElement encodingBindingElement = new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8);
            var httpTransport = new HttpTransportBindingElement();
            var messageSecurity = new AsymmetricSecurityBindingElement();
            messageSecurity.AllowSerializedSigningTokenOnReply = true;
            messageSecurity.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var x509SecurityParamter = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.RawDataKeyIdentifier, SecurityTokenInclusionMode.AlwaysToInitiator);
            messageSecurity.RecipientTokenParameters = x509SecurityParamter;
            messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;

            var initiator = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.RawDataKeyIdentifier, SecurityTokenInclusionMode.AlwaysToRecipient);
            initiator.RequireDerivedKeys = false;
            messageSecurity.InitiatorTokenParameters = initiator;

            var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, httpTransport);

            return customBinding;
        }
    }
}
