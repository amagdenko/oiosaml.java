//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
//-----------------------------------------------------------------------------


using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.IdentityModel.Tokens;
using System.Net.Security;
using System.Text;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Net;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.WSTrust.Bindings;
using Bindings;
using Bindings.ServiceInterfaces;
using Bindings.Data;
using Bindings.MessageContracts;
using Bindings.CustomHeaders;
using Bindings.Bindings;

namespace Client
{
    class Client
    {
        static readonly string SigningCertificateNameSTS = @"CN=DANID A/S - DanID Test + SERIALNUMBER=CVR:30808460-UID:1237552804997, O=DANID A/S // CVR:30808460, C=DK";
        static readonly string SigningCertificateNameService = @"CN=Allan Apoteker + SERIALNUMBER=CVR:25520041-RID:1237281362460, O=TRIFORK SERVICES A/S // CVR:25520041, C=DK";
        static readonly string SigningCertificateNameClient = @"SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALLØSNINGER A/S - TDC Test, O=TDC TOTALLØSNINGER A/S // CVR:25767535, C=DK";

        static readonly string JavaWSPSSLCertificate = @"CN=recht-laptop, OU=Sun Java System Application Server, O=Sun Microsystems, L=Santa Clara, S=California, C=US";

        static void Main(string[] args)
        {
            X509Certificate2 certificate2Client = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);
            X509Certificate2 certificate2Service = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameSTS);
            X509Certificate2 sslCertJavaWSP = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, JavaWSPSSLCertificate);
            EndpointIdentity identity = EndpointIdentity.CreateX509CertificateIdentity(sslCertJavaWSP);


//            Uri uri = new Uri("http://localhost:6020/Echo");
            //            Uri uri = new Uri("https://172.30.161.203:8181/poc-provider/ProviderService");
            Uri uri = new Uri("http://172.30.161.203:8880/poc-provider/ProviderService");
            EndpointAddress address = new EndpointAddress(uri, identity);
            ServicePointManager.ServerCertificateValidationCallback = delegate {
                return (true); 
            };//Removes Validationcheck of SSL certificate, should not be here for Production.

            WSTrustChannelFactory trustChannelFactory = new WSTrustChannelFactory(SecureTokenServiceBindings.GetIssuedTokenBindingNonSSL(), new EndpointAddress(new Uri(@"http://localhost:8080/sts/TokenService"), EndpointIdentity.CreateDnsIdentity("DANID A/S - DanID Test")));
            trustChannelFactory.Credentials.ServiceCertificate.DefaultCertificate = certificate2Service;
            trustChannelFactory.Credentials.ClientCertificate.Certificate = certificate2Client;
            trustChannelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            trustChannelFactory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

            trustChannelFactory.TrustVersion = TrustVersion.WSTrust13;
            var channel = (WSTrustChannel)trustChannelFactory.CreateChannel();
            var bootstrapSecurityToken = MakeBootstrapSecurityToken();
            var rst = MakeOnBehalfOfSTSRequestSecurityToken(bootstrapSecurityToken, certificate2Client, new Uri("http://172.30.161.203:8880/poc-provider/ProviderService"), new List<RequestClaim>());
            var response = channel.Issue(rst);

            
            using (ChannelFactory<IEchoService> factory = new ChannelFactory<IEchoService>(new ServiceproviderBinding(false), address))
            {
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;
                factory.ConfigureChannelFactory();
                factory.Credentials.ClientCertificate.Certificate = certificate2Client;
                factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
                factory.Credentials.ServiceCertificate.DefaultCertificate = CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SigningCertificateNameClient);
                factory.Endpoint.Contract.ProtectionLevel = ProtectionLevel.Sign;

                var pp = ChannelFactoryOperations.CreateChannelWithIssuedToken<IEchoService>(factory, response);

                Structure str = new Structure();
                str.value = "Badabam";
                var echoRequest = new echo();
                echoRequest.Framework = new LibertyFrameworkHeader();
                echoRequest.structureToEcho = str;


                var result = pp.Echo(echoRequest);
                Console.WriteLine("Service returned: {0}", result.structureToEcho.value);

            }
            Console.WriteLine("=====================================");

        }

        public static RequestSecurityToken MakeOnBehalfOfSTSRequestSecurityToken(SecurityToken bootstrapSecurityToken, X509Certificate2 clientCertificate, Uri RelyingPartyAdress, IEnumerable<RequestClaim> requestClaims)
        {
            var requestSecurityToken = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);
            Uri ServiceAddress = RelyingPartyAdress;
            requestSecurityToken.AppliesTo = new EndpointAddress(ServiceAddress);
            requestSecurityToken.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
            requestSecurityToken.KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            requestSecurityToken.OnBehalfOf = new SecurityTokenElement(bootstrapSecurityToken);
            SecurityKeyIdentifierClause clause = new X509RawDataKeyIdentifierClause(clientCertificate);
            requestSecurityToken.UseKey = new UseKey(new SecurityKeyIdentifier(clause), new X509SecurityToken(clientCertificate));

            foreach (RequestClaim claim in requestClaims)
            {
                requestSecurityToken.Claims.Add(claim);
            }

            return requestSecurityToken;
        }

        public static SecurityToken MakeBootstrapSecurityToken()
        {
            Saml2NameIdentifier identifier = new Saml2NameIdentifier("http://localhost/Echo");

            Saml2Assertion assertion = new Saml2Assertion(identifier);

            assertion.Issuer = new Saml2NameIdentifier("idp1.test.oio.dk");
            assertion.Subject = new Saml2Subject(new Saml2NameIdentifier("Casper", new Uri("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")));
            Saml2Attribute atribute = new Saml2Attribute("dk:gov:saml:attribute:AssuranceLevel", "2");
            atribute.NameFormat = new Uri("urn:oasis:names:tc:SAML:2.0:attrname-format:basic");

            assertion.Statements.Add(new Saml2AttributeStatement(atribute));
            return new Saml2SecurityToken(assertion);
        }
    }

}
