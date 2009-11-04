//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
//-----------------------------------------------------------------------------


using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;

using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens.Saml2;
using Bindings;
using Bindings.Bindings;

namespace SimpleActiveSTS
{
    class SimpleActiveSTS
    {
        static readonly string SigningCertificateName = "CN=localhost";

        static void Main( string[] args )
        {
            // Create and setup the configuration for our STS
            SigningCredentials signingCreds = new X509SigningCredentials( CertificateUtil.GetCertificate( StoreName.My, StoreLocation.LocalMachine, SigningCertificateName ) );
            SecurityTokenServiceConfiguration config = new SecurityTokenServiceConfiguration( "http://SimpleActiveSTS", signingCreds );
            
            //Enabling SAML 2.0 Token 
            config.DefaultTokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
//            config.DefaultTokenType = Microsoft.IdentityModel.Tokens.SecurityTokenTypes.OasisWssSaml2TokenProfile11;
            
            // Disable the use of security context token (SCT) from the binding between the client and the STS
            //WS2007HttpBinding ws2007HttpBinding = new WS2007HttpBinding();
            //ws2007HttpBinding.Security.Message.EstablishSecurityContext = false;
            ////ws2007HttpBinding.Security.Message.NegotiateServiceCredential = false;
            //CustomBinding cbtemp = new CustomBinding(ws2007HttpBinding.CreateBindingElements());
            //var securityBinding = cbtemp.Elements.Find<SecurityBindingElement>();
            //securityBinding.OptionalEndpointSupportingTokenParameters.Endorsing.Add(new RsaSecurityTokenParameters());
            //CustomBinding cb = new CustomBinding(securityBinding, new TextMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8), new HttpTransportBindingElement());

            Binding cb = SecureTokenServiceBindings.GetIssuedTokenBindingNonSSL();

            // Add the STS endoint information
            config.TrustEndpoints.Add(new ServiceHostEndpointConfiguration(typeof(IWSTrust13SyncContract), cb, "http://localhost:6000/SimpleActiveSTS"));

            // Set the STS implementation class type
            config.SecurityTokenService = typeof( MySecurityTokenService );


            // Create the WS-Trust service host with our STS configuration
            using ( WSTrustServiceHost host = new WSTrustServiceHost( config, new Uri( "http://localhost:6000/SimpleActiveSTS" ) ) )
            {
                //ADDED LATER ONLY FOR WAVE 2 NOT APPLICABLE FOR BETA2 
                host.Credentials.IssuedTokenAuthentication.AudienceUriMode = System.IdentityModel.Selectors.AudienceUriMode.Never;
                host.Credentials.ServiceCertificate.Certificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateName);
                host.SecurityTokenServiceConfiguration.SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.OnBehalfOf] =
                new SecurityTokenHandlerCollection(new List<SecurityTokenHandler> { new Saml2SecurityTokenHandler() });
                
                host.Open();
                Console.WriteLine( "SimpleActiveSTS started, press ENTER to stop ..." );
                Console.ReadLine();
                host.Close();
            }
        }
    }
}
