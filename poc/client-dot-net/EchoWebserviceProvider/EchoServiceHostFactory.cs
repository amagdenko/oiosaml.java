using System;
using System.Net.Security;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Channels;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml11;
using OIOSaml.Serviceprovider.Binding;

namespace EchoWebserviceProvider
{
    public class EchoServiceHostFactory : ServiceHostFactoryBase
    {
        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {
            ServiceHost serviceHost = new EchoServiceHost(baseAddresses);
            Binding oioBinding = new OIOServiceproviderBinding();
            serviceHost.AddServiceEndpoint("EchoWebserviceProvider.IEchoService", oioBinding, "Echo");

            FederatedServiceCredentials.ConfigureServiceHost(serviceHost);

            return serviceHost;
        }
    }
         
}