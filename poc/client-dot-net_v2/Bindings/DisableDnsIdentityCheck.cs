using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IdentityModel.Policy;
using System.ServiceModel;
using System.ServiceModel.Security;

namespace Bindings
{
    public class DisabledDnsIdentityCheck : IdentityVerifier
    {
        public override bool CheckAccess(EndpointIdentity identity, AuthorizationContext authContext)
        {
            return true;
        }

        public override bool TryGetIdentity(EndpointAddress reference, out EndpointIdentity identity)
        {
            identity = EndpointIdentity.CreateDnsIdentity(reference.Uri.Host);
            return true;
        }
    }
}
