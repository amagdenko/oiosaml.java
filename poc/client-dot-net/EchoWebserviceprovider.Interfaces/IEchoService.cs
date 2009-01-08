using System.Net.Security;
using System.ServiceModel;
using EchoWebserviceprovider.Interfaces;
using OIOSaml.Serviceprovider.Headers;
using System;
using System.Runtime.Serialization;

namespace EchoWebserviceProvider
{

    [ServiceContract(Name = "Provider", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    [XmlSerializerFormat]
    public interface IEchoService2
    {
        [OperationContract(ReplyAction = "http://provider.poc.saml.itst.dk/Provider/echoResponse", Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        [FaultContractAttribute(typeof(FrameworkFault), ProtectionLevel = ProtectionLevel.Sign)]
        echoResponse Echo(echo structureToEcho);    
    }

    [MessageContract()]
    public class echo
    {                               
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework", ProtectionLevel = ProtectionLevel.Sign)]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }

    [MessageContract()]
    public class echoResponse
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework", ProtectionLevel = ProtectionLevel.Sign)]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }

    [DataContract]
    public class FrameworkFault
    {
        public FrameworkFault()
        {
        }
        public FrameworkFault(string error)
        {
            Details = error;
        }
        [DataMember]
        public string Details { get; set; }
    }
}