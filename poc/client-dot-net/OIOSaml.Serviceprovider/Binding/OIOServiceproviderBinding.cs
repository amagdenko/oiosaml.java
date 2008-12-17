using System;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Microsoft.IdentityModel.Tokens.Saml2;

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
            messageSecurity.AllowSerializedSigningTokenOnReply = true;
            messageSecurity.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            messageSecurity.RecipientTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.AlwaysToInitiator);
            messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;

            var initiator = new IssuedSecurityTokenParameters("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
            initiator.KeyType = SecurityKeyType.AsymmetricKey;
            initiator.RequireDerivedKeys = false;
         
            messageSecurity.InitiatorTokenParameters = initiator;

            var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, httpTransport);

            return customBinding;
        }

        public static System.ServiceModel.Channels.Binding GetSecurityTokenServiceBinding()
        {
            WS2007HttpBinding binding = new WS2007HttpBinding(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
            // If the security mode is message, then the secure session settings are the protection token parameters.

            return binding;
        }
       
     

    }
}