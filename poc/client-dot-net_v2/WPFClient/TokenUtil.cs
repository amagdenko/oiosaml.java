using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Security.Cryptography.X509Certificates;
using Bindings.TokenClient;
using System.ServiceModel;
using EchoService.ServiceInterfaces;
using System.Net.Security;
using Bindings.Bindings;
using Bindings.CustomHeaders;
using EchoService.MessageContracts;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Bindings.Data;

namespace WPFClient
{
    public class TokenUtil
    {
        static readonly string SigningCertificateNameSTS = @"CN=DANID A/S - DanID Test + SERIALNUMBER=CVR:30808460-UID:1237552804997, O=DANID A/S // CVR:30808460, C=DK";
        // static readonly string SigningCertificateNameClient = @"CN=Allan Apoteker + SERIALNUMBER=CVR:25520041-RID:1237281362460, O=TRIFORK SERVICES A/S // CVR:25520041, C=DK";

        public static SecurityToken MakeBootstrapSecurityToken(string issuer)
        {
            Saml2NameIdentifier identifier = new Saml2NameIdentifier(issuer);

            Saml2Assertion assertion = new Saml2Assertion(identifier);

            assertion.Issuer = new Saml2NameIdentifier("idp1.test.oio.dk");
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("Test", new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")));
            Saml2Attribute atribute = new Saml2Attribute("dk:gov:saml:attribute:AssuranceLevel", "2");
            atribute.NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

            assertion.Statements.Add(new Saml2AttributeStatement(atribute));
            return new Saml2SecurityToken(assertion);
        }

        public static SecurityToken GetIssuedToken(string STSUrl, string audience, string signingCertificateNameClient, SecurityToken bootstrapToken)
        {
            
            var certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, signingCertificateNameClient);
            var certificate2Service = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameSTS);
            return TokenClient.GetIssuedToken(new Uri(audience), certificate2Client, certificate2Service, new Uri(STSUrl), bootstrapToken);
        }

        public static string ExecuteWS(string signingCertificateNameClient, string address, SecurityToken issuedToken)
        {
            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, signingCertificateNameClient);
            ChannelFactory<IEchoService> factory = null;

            try
            {

                factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, "CN=STS");// SigningCertificateNameGenevaService);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var service = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, issuedToken);

                Structure str = new Structure();
                str.value = "Testing .NET client";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;

                echoResponse result = null;
                result = service.Echo(echoRequest);

                return result.structureToEcho.value;
            }

            catch (Exception e)
            {
                if (factory != null && factory.State == CommunicationState.Opened)
                {
                    factory.Close();
                }

                throw;
            }
            finally
            {
                if (factory.State == CommunicationState.Opened)
                {
                    factory.Close();
                }
            }
        }
    }
}
