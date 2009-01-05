using System;
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
            Binding oioBinding = new ServiceproviderBinding();
            serviceHost.AddServiceEndpoint("EchoWebserviceProvider.IEchoService", oioBinding, "Echo");

            OIOFederatedServiceCredentials.ConfigureServiceHost(serviceHost);

            var federatedCredentials = (FederatedServiceCredentials)serviceHost.Credentials;

            // Remove the default ServiceCredentials behavior.
            serviceHost.Description.Behaviors.Remove<ServiceCredentials>();

            serviceHost.Description.Behaviors.Add(new OIOSaml.Serviceprovider.Saml2GenevaFix.OIOFederatedServiceCredentials(federatedCredentials));
            return serviceHost;
        }
    }
         
}