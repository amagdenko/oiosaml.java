using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using Microsoft.IdentityModel.Protocols.WSTrust;
using OIOSaml.Serviceprovider.Binding;

namespace OIOSaml.Serviceprovider.ClientFactories
{
    public class WebserviceproviderChannelFactory
    {
        public static T CreateChannelWithIssuedToken<T>(SecurityToken token, X509Certificate2 clientCertificate, X509Certificate2 serviceCertificate, EndpointAddress serviceEndpointAddress)
        {
            bool sslEnabled = serviceEndpointAddress.Uri.Scheme.ToLowerInvariant() == "https";

            ChannelFactory<T> echoServiceFactory = new ChannelFactory<T>(new ServiceproviderBinding(sslEnabled), serviceEndpointAddress);


            echoServiceFactory.Credentials.ClientCertificate.Certificate = clientCertificate;

            //Issuedtoken binding information needs to be set, even though it aint used.
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerBinding = new SecurityTokenServiceBinding();
            echoServiceFactory.Credentials.IssuedToken.LocalIssuerAddress = new EndpointAddress(new Uri("http://NotAnUrlAndNotToBeUsed"));

            echoServiceFactory.Credentials.ServiceCertificate.DefaultCertificate = serviceCertificate;

            ExchangeClientCredentialsWithFederatedClientCredentials(echoServiceFactory);

            return echoServiceFactory.CreateChannelWithIssuedToken(token);
        }

        private static void ExchangeClientCredentialsWithFederatedClientCredentials<T>(ChannelFactory<T> echoServiceFactory)
        {
            ClientCredentials other = echoServiceFactory.Endpoint.Behaviors.Find<ClientCredentials>();
            if (other != null)
            {
                echoServiceFactory.Endpoint.Behaviors.Remove(other.GetType());
            }
            FederatedClientCredentials item = null;
            if (other != null)
            {
                item = new FederatedClientCredentials(other);
            }
            echoServiceFactory.Endpoint.Behaviors.Add(item);
        }
    }
}
