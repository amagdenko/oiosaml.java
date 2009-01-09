using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.ServiceModel;
using System.Text;
using OIOSaml.Serviceprovider.Headers;

namespace EchoWebserviceprovider.Interfaces
{
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
}
