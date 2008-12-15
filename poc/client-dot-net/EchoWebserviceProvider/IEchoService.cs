using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.Text;

namespace EchoWebserviceProvider
{
    [ServiceContract(Name = "ProviderService", Namespace = "http://provider.poc.saml.itst.dk/", ProtectionLevel = ProtectionLevel.Sign)]
    public interface IEchoService
    {
        [OperationContract(Action = "http://provider.poc.saml.itst.dk/Provider/echoRequest", Name="echo" )]
        Structure Echo(Structure structureToEcho);
    }
}