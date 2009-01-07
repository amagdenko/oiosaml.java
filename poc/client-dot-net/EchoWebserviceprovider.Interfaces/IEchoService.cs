using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Text;
using OIOSaml.Serviceprovider.Headers;

namespace EchoWebserviceProvider
{
    //[ServiceContract(Name = "ProviderService", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    //public interface IEchoService
    //{
    //    [OperationContract(Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name="echo", ProtectionLevel = ProtectionLevel.Sign)]
    //    Structure Echo(Structure structureToEcho);
    //}

    [MessageContract]
    public class EchoMessage
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework")]
        public LibertyFrameworkHeader Framework;
        //[MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "echo", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }

    [ServiceContract(Name = "ProviderService", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    [XmlSerializerFormat]    
    public interface IEchoService2
    {
        [OperationContract(Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name = "echo", ProtectionLevel = ProtectionLevel.Sign)]
        EchoMessage Echo(EchoMessage structureToEcho);
    }
}