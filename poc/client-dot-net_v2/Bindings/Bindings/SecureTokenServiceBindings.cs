using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.ServiceModel;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Security;
using System.Net;
using System.IdentityModel.Policy;
using System.IdentityModel.Tokens;

namespace Bindings.Bindings
{
    public class SecureTokenServiceBindings
    {
        public static Binding GetIssuedTokenBindingSSL()
        {
            var textmessageEncoding = new TextMessageEncodingBindingElement();
            textmessageEncoding.WriteEncoding = Encoding.UTF8;
            textmessageEncoding.MessageVersion = MessageVersion.Soap11WSAddressing10;

            var messageSecurity = new AsymmetricSecurityBindingElement();
            messageSecurity.AllowSerializedSigningTokenOnReply = true;
            messageSecurity.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var x509SecurityParamter = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.RawDataKeyIdentifier, SecurityTokenInclusionMode.AlwaysToInitiator);
            messageSecurity.RecipientTokenParameters = x509SecurityParamter;
            messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;
            var initiator = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.RawDataKeyIdentifier, SecurityTokenInclusionMode.AlwaysToRecipient);
            initiator.RequireDerivedKeys = false;
            messageSecurity.InitiatorTokenParameters = initiator;

            messageSecurity.MessageProtectionOrder = MessageProtectionOrder.SignBeforeEncrypt;

            return new CustomBinding(
                messageSecurity,
                textmessageEncoding,
                new HttpsTransportBindingElement());
        }

        public static System.ServiceModel.Channels.Binding GetIssuedTokenBindingNonSSL()
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
