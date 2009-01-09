using System.Net.Security;
using System.ServiceModel;
using OIOSaml.Serviceprovider.Headers;

namespace EchoWebserviceprovider.Interfaces
{

    /// <summary>
    /// Libertyheader must always be included on WCP calls
    /// </summary>
    [MessageContract]
    public class echo
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework", ProtectionLevel = ProtectionLevel.Sign)]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }

    [MessageContract]
    public class echoResponse
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework", ProtectionLevel = ProtectionLevel.Sign)]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }
}
