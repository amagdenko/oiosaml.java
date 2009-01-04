using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Samples.TrustClient;
using OIOSaml.Serviceprovider.Binding;

/// <summary>
    /// Creates service instance to handle incoming request.
    /// </summary>
    public class SecureTokenServiceHostFactory : WSTrustServiceHostFactory
    {
        public override ServiceHostBase CreateServiceHost(string constructorString, Uri[] baseAddresses)
        {
            ServiceHostBase serviceHost = base.CreateServiceHost(constructorString, baseAddresses);
            serviceHost.Credentials.ServiceCertificate.Certificate = CertificateUtil.GetCertificate("CN=localhost",
                                                                                                    StoreLocation.
                                                                                                        LocalMachine,
                                                                                                    StoreName.My);

            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(
        delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            return (true);
        });

            serviceHost.AddServiceEndpoint("Microsoft.IdentityModel.Protocols.WSTrust.IWSTrust13SyncContract", GetSecurityTokenServiceBinding(),
                                           new Uri("http://lh-z3jyrnwtj9d7/OIOSamlSTS/Service.svc"));

            return serviceHost;
        }

        private static Binding GetSecurityTokenServiceBinding()
        {
            //
            // Use the standard WS2007HttpBinding
            //
            WS2007HttpBinding binding = new WS2007HttpBinding();
            binding.Security.Message.EstablishSecurityContext = false;

            return binding;
        }
    }


