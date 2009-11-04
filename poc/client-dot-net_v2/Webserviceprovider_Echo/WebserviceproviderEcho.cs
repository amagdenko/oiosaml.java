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
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Threading;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.IdentityModel.Tokens;
using System.Net.Security;
using Bindings;
using Bindings.ServiceInterfaces;
using Bindings.Bindings;

namespace ClaimsAwareWebService
{
    

    public class WebserviceproviderEcho 
    {
        static void Main( string[] args )
        {
            Uri serviceUri = new Uri( "http://localhost:6020/Echo" );
            using ( ServiceHost host = new ServiceHost( typeof( EchoService ), serviceUri ) )
            {
                host.AddServiceEndpoint(typeof(IEchoService), new ServiceproviderBinding(false), "");

                // Configure our certificate and issuer certificate validation settings on the service credentials
                host.Credentials.ServiceCertificate.SetCertificate( "CN=localhost", StoreLocation.LocalMachine, StoreName.My );
                host.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;

                // Enable metadata generation via HTTP GET
                ServiceMetadataBehavior smb = new ServiceMetadataBehavior();
                smb.HttpGetEnabled = true;
                host.Description.Behaviors.Add( smb );
                            
                host.AddServiceEndpoint(typeof( IMetadataExchange), MetadataExchangeBindings.CreateMexHttpBinding(), "mex" );


                // Configure the service host to use the Geneva Framework
                ServiceConfiguration configuration = new ServiceConfiguration();
                configuration.IssuerNameRegistry = new TrustedIssuerNameRegistry();
                configuration.SecurityTokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add( new Uri("http://localhost/Echo/service.svc/Echo") );

                FederatedServiceCredentials.ConfigureServiceHost( host, configuration );

                //ADDED LATER ONLY FOR WAVE 2 NOT APPLICABLE FOR BETA2 
                host.Credentials.IssuedTokenAuthentication.AudienceUriMode = System.IdentityModel.Selectors.AudienceUriMode.Never;
              
                host.Open();

                Console.WriteLine( "ClaimsAwareWebService started, press ENTER to stop ..." );
                Console.ReadLine();

                host.Close();
            }

        }
    }
}
