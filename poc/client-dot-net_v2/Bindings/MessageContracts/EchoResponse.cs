using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;
using Bindings.CustomHeaders;
using Bindings.Data;
using System.Net.Security;

namespace Bindings.MessageContracts
{
    [MessageContract]
    public class echoResponse
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework", ProtectionLevel = ProtectionLevel.Sign)]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }
}
