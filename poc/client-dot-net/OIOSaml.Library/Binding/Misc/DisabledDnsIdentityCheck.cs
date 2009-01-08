using System.IdentityModel.Policy;
using System.ServiceModel;
using System.ServiceModel.Security;

namespace OIOSaml.Serviceprovider.Binding.Misc
{
    /// <summary>
    /// Disables dnsidentitychecks for services and the identity for the relying party service certificat.
    /// </summary>
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