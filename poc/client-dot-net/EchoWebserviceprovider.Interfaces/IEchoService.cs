using System.Net.Security;
using System.ServiceModel;

namespace EchoWebserviceprovider.Interfaces
{
    [ServiceContract(Name = "Provider", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    [XmlSerializerFormat]
    public interface IEchoService
    {
        [OperationContract(ReplyAction = "http://provider.poc.saml.itst.dk/Provider/echoResponse", Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        [FaultContractAttribute(typeof(FrameworkFault), ProtectionLevel = ProtectionLevel.Sign)]
        echoResponse Echo(echo structureToEcho);    
    }
}