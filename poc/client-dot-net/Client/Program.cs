using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Text;
using Client.ServiceReference1;
using EchoWebserviceProvider;
using Microsoft.IdentityModel.Samples.TrustClient;
using System.Security.Cryptography.X509Certificates;
using OIOSaml.Serviceprovider.Binding;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            ServiceReference1.ProviderServiceClient client = new ServiceReference1.ProviderServiceClient();
            client.Endpoint.Binding = new OIOServiceproviderBinding();
            client.ClientCredentials.ClientCertificate.Certificate = CertificateUtil.GetCertificate("4036ac0b", StoreLocation.LocalMachine, StoreName.My);

            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(
 delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
 {
     return (true);
 });

            client.echo(new Structure());
        }
    }
}
