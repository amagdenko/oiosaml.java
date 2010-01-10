using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Text;
using System.ServiceModel.Activation;
using Bindings.ServiceInterfaces;
using Bindings.Bindings;
using System.ServiceModel.Security;
using System.ServiceModel.Description;
using ClaimsAwareWebService;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace IssHosted
{
    public class DerivedFactoryServiceHost : ServiceHostFactory
    {
        //static readonly string SigningCertificateNameGenevaService = @"CN=Allan Apoteker + SERIALNUMBER=CVR:25520041-RID:1237281362460, O=TRIFORK SERVICES A/S // CVR:25520041, C=DK";
        static readonly string SigningCertificateNameGenevaService = @"CN=STS";
        static readonly string SigningCertificateNameClient = @"SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK";
        static readonly string JavaWSPSSLCertificate = @"CN=recht-laptop, OU=Sun Java System Application Server, O=Sun Microsystems, L=Santa Clara, S=California, C=US";
        static readonly string SigningCertificateNameJavaService = @"SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK";

        protected override ServiceHost CreateServiceHost(Type t, Uri[] baseAddresses)
        {
            return CreateServiceHost(t, baseAddresses);
        }

        public override ServiceHostBase CreateServiceHost
                (string service, Uri[] baseAddresses)
        {
            ServiceHost host = new ServiceHost(typeof(EchoService),
                baseAddresses);

            host.AddServiceEndpoint(typeof(IEchoService), new ServiceproviderBinding(true), "");
            host.AddServiceEndpoint(typeof(IEchoService), new ServiceproviderBinding(false), "");

            // Configure our certificate and issuer certificate validation settings on the service credentials
            host.Credentials.ServiceCertificate.SetCertificate(SigningCertificateNameGenevaService, StoreLocation.LocalMachine, StoreName.My);
            // Enable metadata generation via HTTP GET
            ServiceMetadataBehavior smb = new ServiceMetadataBehavior();
            smb.HttpsGetEnabled = true;
            smb.HttpGetEnabled = true;
            host.Description.Behaviors.Add(smb);

            host.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexHttpsBinding(), "mex");
            host.AddServiceEndpoint(typeof(IMetadataExchange), MetadataExchangeBindings.CreateMexHttpBinding(), "mex");


            // Configure the service host to use the Geneva Framework
            ServiceConfiguration configuration = new ServiceConfiguration();
            configuration.IssuerNameRegistry = new TrustedIssuerNameRegistry();
            configuration.SecurityTokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri("http://localhost/Echo/service.svc/Echo"));
            configuration.SecurityTokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri("http://localhost:6020/Echo"));
            configuration.SecurityTokenHandlers.Configuration.AudienceRestriction.AllowedAudienceUris.Add(new Uri("https://172.30.161.162:8181/poc-provider/ProviderService"));

            FederatedServiceCredentials.ConfigureServiceHost(host, configuration);
            return host;
        }

    }

}
