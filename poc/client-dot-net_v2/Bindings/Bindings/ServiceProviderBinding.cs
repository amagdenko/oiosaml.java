using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.Net;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using OIOSaml.Serviceprovider.Binding.Misc;

namespace Bindings.Bindings
{
    public class ServiceproviderBinding : CustomBinding
    {
        public ServiceproviderBinding(bool isSslEnabled)
            : base(Create(isSslEnabled))
        {
        }

        private static System.ServiceModel.Channels.Binding Create(bool sslEnabled)
        {
            if (sslEnabled)
            {

                var httpsTransport = new TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration();
               
                return CreateBinding(httpsTransport);
            }
            else
            {
                var httptransport = new HttpTransportBindingElement();
                httptransport.AuthenticationScheme = AuthenticationSchemes.Anonymous;
                httptransport.ProxyAuthenticationScheme = AuthenticationSchemes.Anonymous;

                return CreateBinding(httptransport);
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="transport"></param>
        /// <returns></returns>
        private static System.ServiceModel.Channels.Binding CreateBinding(TransportBindingElement transport)
        {
            TextMessageEncodingBindingElement encodingBindingElement = new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8);

            var messageSecurity = new AsymmetricSecurityBindingElement();
            messageSecurity.LocalClientSettings.IdentityVerifier = new DisabledDnsIdentityCheck();

            messageSecurity.AllowSerializedSigningTokenOnReply = true;
            messageSecurity.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            messageSecurity.RecipientTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.AlwaysToInitiator);
            messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;
            var initiator = new IssuedSecurityTokenParameters("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
            initiator.ProtectTokens = true;
            initiator.UseStrTransform = true;
            initiator.KeyType = SecurityKeyType.AsymmetricKey;
            initiator.RequireDerivedKeys = false;
            messageSecurity.InitiatorTokenParameters = initiator;


            var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, transport);

            return customBinding;
        }
    }
}
