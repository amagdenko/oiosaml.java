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
            serviceHost.AddServiceEndpoint("EchoWebserviceprovider.Interfaces.IEchoService", sslOioBinding, "Echo");

            Binding oioBinding = new ServiceproviderBinding(false);
            serviceHost.AddServiceEndpoint("EchoWebserviceprovider.Interfaces.IEchoService", oioBinding, "Echo");
            
            ServicePointManager.ServerCertificateValidationCallback = delegate { return (true); };//Removes Validationcheck of SSL certificate, should not be here for Production.

            OIOFederatedServiceCredentials.Setup(serviceHost);

            return serviceHost;
        }
    }
         
}