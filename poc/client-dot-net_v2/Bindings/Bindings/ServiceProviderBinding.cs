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
                return null;
                //var httpsTransport = new TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration();
                //return CreateBinding(httpsTransport);
            }
            else
            {
                var httptransport = new HttpTransportBindingElement();
                httptransport.AuthenticationScheme = AuthenticationSchemes.Anonymous;
                httptransport.ProxyAuthenticationScheme = AuthenticationSchemes.Anonymous;

                return CreateBinding(httptransport);
            }
        }

        ///Oprindelig oio binding, men laver ikke STR transform fordi MS ikke understøtter det.
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
            initiator.UseStrTransform = true;
            initiator.KeyType = SecurityKeyType.AsymmetricKey;
            initiator.RequireDerivedKeys = false;
            messageSecurity.InitiatorTokenParameters = initiator;


            var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, transport);

            return customBinding;
        }

        ///Laver str transform men 2 identiske id'er
        //private static System.ServiceModel.Channels.Binding CreateBinding(TransportBindingElement transport)
        //{
        //    TextMessageEncodingBindingElement encodingBindingElement = new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8);

        //    var messageSecurity = new AsymmetricSecurityBindingElement();
        //    messageSecurity.LocalClientSettings.IdentityVerifier = new DisabledDnsIdentityCheck();
        //    messageSecurity.MessageProtectionOrder = MessageProtectionOrder.SignBeforeEncrypt;
        //    messageSecurity.AllowSerializedSigningTokenOnReply = false;
        //    messageSecurity.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
        //    messageSecurity.RecipientTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.AlwaysToInitiator);
        //    messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;
        //    var initiator = new IssuedSecurityTokenParameters("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        //    initiator.UseStrTransform = true;
        //    initiator.KeyType = SecurityKeyType.AsymmetricKey;
        //    initiator.RequireDerivedKeys = false;
        //    initiator.ReferenceStyle = SecurityTokenReferenceStyle.Internal;
        //    messageSecurity.InitiatorTokenParameters = initiator;
        //    messageSecurity.EndpointSupportingTokenParameters.Signed.Add(initiator);
        //    messageSecurity.EndpointSupportingTokenParameters.SetKeyDerivation(false);


        //    var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, transport);

        //    return customBinding;
        //}

        //private static System.ServiceModel.Channels.Binding CreateBinding(TransportBindingElement transport)
        //{
        //    X509SecurityTokenParameters recipientSecurityTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.Never);
        //    recipientSecurityTokenParameters.RequireDerivedKeys = false;
        //    IssuedSecurityTokenParameters issuedTokenParameter = new IssuedSecurityTokenParameters("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        //    issuedTokenParameter.KeyType = SecurityKeyType.AsymmetricKey;
        //    issuedTokenParameter.InclusionMode = SecurityTokenInclusionMode.AlwaysToRecipient;
        //    issuedTokenParameter.UseStrTransform = true;
        //    issuedTokenParameter.RequireDerivedKeys = false;
        //    AsymmetricSecurityBindingElement asbe = new AsymmetricSecurityBindingElement(recipientSecurityTokenParameters, issuedTokenParameter);
        //    asbe.AllowSerializedSigningTokenOnReply = false;
        //    asbe.EndpointSupportingTokenParameters.SetKeyDerivation(false);
        //    asbe.MessageProtectionOrder = MessageProtectionOrder.SignBeforeEncrypt;
        //    asbe.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
        //    asbe.LocalClientSettings.IdentityVerifier = new DisabledDnsIdentityCheck();

        //    asbe.EndpointSupportingTokenParameters.Signed.Add(issuedTokenParameter);
        //    CustomBinding customBinding = new CustomBinding(
        //        asbe,
        //         new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8),
        //        transport);
        //    return customBinding;
        //}
        //private static System.ServiceModel.Channels.Binding CreateBinding(TransportBindingElement transport)
        //{
        //    TextMessageEncodingBindingElement encodingBindingElement = new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8);

        //    var messageSecurity = new AsymmetricSecurityBindingElement();
        //    messageSecurity.LocalClientSettings.IdentityVerifier = new DisabledDnsIdentityCheck();

        //    messageSecurity.AllowSerializedSigningTokenOnReply = true;
        //    messageSecurity.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
        //    messageSecurity.RecipientTokenParameters = new X509SecurityTokenParameters(X509KeyIdentifierClauseType.Any, SecurityTokenInclusionMode.AlwaysToInitiator);
        //    messageSecurity.RecipientTokenParameters.RequireDerivedKeys = false;
        //    var initiator = new IssuedSecurityTokenParameters("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        //    initiator.UseStrTransform = true;
        //    initiator.KeyType = SecurityKeyType.AsymmetricKey;
        //    initiator.RequireDerivedKeys = false;
        //    messageSecurity.InitiatorTokenParameters = initiator;


        //    var customBinding = new CustomBinding(encodingBindingElement, messageSecurity, transport);

        //    return customBinding;
        //}
    }
}
