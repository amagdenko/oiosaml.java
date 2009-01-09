using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Samples.TrustClient;
using NUnit.Framework;
using Microsoft.IdentityModel.SecurityTokenService;
using OIOSaml.Serviceprovider.ClientFactories;

namespace Client
{
    [TestFixture]
    public class TestWSTrustClientInteroperability
    {
        X509Certificate2 clientCertifikat = CertificateUtil.GetCertificate("SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK", StoreLocation.LocalMachine, StoreName.My);

        X509Certificate2 serviceCertifikat = CertificateUtil.GetCertificate("SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK", StoreLocation.LocalMachine, StoreName.My);
        private const string DnsIdentityForServiceCertificates = "TDC TOTALLØSNINGER A/S - TDC Test";

        Uri STSAddress = new Uri("http://10.1.1.101:8081/sts/TokenService"); //Joakims Ip
   //     Uri STSAddress = new Uri("http://213.237.161.81:8082/sts/TokenService");

        List<RequestClaim> requestClaims = new List<RequestClaim>();

        [Test]
        public void GetSaml2SecurityTokenFromJavaSTS()
        {
            SecurityToken bootstrapSecurityToken = BootstrapSecurityTokenGenerator.MakeBootstrapSecurityToken();

            RequestSecurityToken rst = WSTrustClientFactory.MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, clientCertifikat, new Uri("http://localhost/Echo/service.svc/Echo"), requestClaims);

            GenericXmlSecurityToken token = GetIssuedToken(rst);

            Assert.IsTrue(token.InternalTokenReference.ToString().Contains("Saml2"));
        }

        public GenericXmlSecurityToken GetIssuedToken(RequestSecurityToken rst)
        {
            EndpointAddress endpointAddress = new EndpointAddress(STSAddress, EndpointIdentity.CreateDnsIdentity(DnsIdentityForServiceCertificates));
            WSTrustClient trustClient = WSTrustClientFactory.GetWSTrustClient(clientCertifikat, serviceCertifikat, endpointAddress);

            GenericXmlSecurityToken token = (GenericXmlSecurityToken) trustClient.Issue(rst);
            trustClient.Close();
            return token;
        }

        
    }
}
