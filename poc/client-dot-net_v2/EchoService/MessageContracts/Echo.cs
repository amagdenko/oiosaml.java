using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Bindings.CustomHeaders;
using Bindings.Data;
using System.Net.Security;
using System.ServiceModel;

namespace EchoService.MessageContracts
{
    /// <summary>
    /// Libertyheader must always be included on WCP calls
    /// </summary>
    [System.ServiceModel.MessageContract]
    public class echo
    {
        [MessageHeader(Namespace = "urn:liberty:sb:2006-08", MustUnderstand = true, Name = "Framework", ProtectionLevel = ProtectionLevel.Sign)]
        public LibertyFrameworkHeader Framework;
        [MessageBodyMember(Namespace = "http://provider.poc.saml.itst.dk/", Name = "structure", ProtectionLevel = ProtectionLevel.Sign)]
        public Structure structureToEcho;
    }
}
