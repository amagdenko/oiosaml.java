using System.Net.Security;
using System.ServiceModel;
using Bindings.MessageContracts;
using Bindings.Data;

namespace Bindings.ServiceInterfaces
{
    /// <summary>
    /// Uses xmlserializer instead of DataContractSerializer(DCS). Reason for this is, DCS serializes all datamembers as XMLElements. Attributes is desired in the LibertyFrameworkHeader
    /// 
    /// </summary>
    [ServiceContract(Name = "Provider", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    [XmlSerializerFormat]
    public interface IEchoService
    {
        [OperationContract(ReplyAction = "http://provider.poc.saml.itst.dk/Provider/echoResponse", Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        [FaultContractAttribute(typeof(FrameworkFault), ProtectionLevel = ProtectionLevel.Sign)]
        echoResponse Echo(echo structureToEcho);
    }
}
