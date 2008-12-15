using System;
using System.Net.Security;
using System.ServiceModel;
using System.ServiceModel.Activation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml11;

namespace EchoWebserviceProvider
{
    public class EchoServiceHostFactory : ServiceHostFactoryBase
    {
        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {
            ServiceHost serviceHost = new EchoServiceHost(baseAddresses);
            serviceHost.AddServiceEndpoint("EchoWebserviceProvider.IEchoService", BindingFactory.CreateAsymmetricBinding(), "Echo");

            FederatedServiceCredentials.ConfigureServiceHost(serviceHost);

            return serviceHost;
        }
    }
         
}