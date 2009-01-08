using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using Microsoft.IdentityModel.Tokens;
using OIOSaml.Serviceprovider.Binding;
using OIOSaml.Serviceprovider.Saml2GenevaFix;


namespace EchoWebserviceProvider
{
    public class EchoServiceHostFactory : ServiceHostFactoryBase
    {
        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {
            ServiceHost serviceHost = new EchoServiceHost(baseAddresses);
            Binding sslOioBinding = new ServiceproviderBinding(true);
            serviceHost.AddServiceEndpoint("EchoWebserviceProvider.IEchoService2", sslOioBinding, "Echo");

            Binding oioBinding = new ServiceproviderBinding(false);
            serviceHost.AddServiceEndpoint("EchoWebserviceProvider.IEchoService2", oioBinding, "Echo");
            
            ServicePointManager.ServerCertificateValidationCallback = delegate { return (true); };
            
            FederatedServiceCredentials.ConfigureServiceHost(serviceHost);

            var federatedCredentials = (FederatedServiceCredentials)serviceHost.Credentials;

            // Remove the default ServiceCredentials behavior.
            serviceHost.Description.Behaviors.Remove<ServiceCredentials>();

            serviceHost.Description.Behaviors.Add(new OIOFederatedServiceCredentials(federatedCredentials));
           
            return serviceHost;
        }
    }
         
}