using System.Threading;
using Microsoft.IdentityModel.Claims;

namespace EchoWebserviceProvider
{
    public class EchoService : IEchoService
    {
        public Structure Echo(Structure structureToEcho)
        {
            var principal = Thread.CurrentPrincipal as ClaimsPrincipal;
              

            var str = new Structure();
            if (principal != null)
                str.value = principal.ToString();
            else
            {
                str.value = "null";
            }
            return str;
        }
    }
}
