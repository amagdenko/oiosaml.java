using System.Net.Security;
using System.ServiceModel;
using EchoWebserviceprovider.Interfaces;
using OIOSaml.Serviceprovider.Headers;

namespace EchoWebserviceProvider
{
    //[ServiceContract(Name = "ProviderService", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    //public interface IEchoService
    //{
    //    [OperationContract(Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name="echo", ProtectionLevel = ProtectionLevel.Sign)]
    //    Structure Echo(Structure structureToEcho);
    //}
    [ServiceContract(Name = "ProviderService", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    [XmlSerializerFormat]
    public interface IEchoService2
    {
        [OperationContract(Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name = "echo", ProtectionLevel = ProtectionLevel.Sign)]
        echoResponse Echo(echo structureToEcho);
    }

    [MessageContract()]
    public class echo
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework")]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "echo", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }

    [MessageContract()]
    public class echoResponse
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework")]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "echo", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }
}