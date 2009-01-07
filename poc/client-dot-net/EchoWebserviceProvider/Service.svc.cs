using System.ServiceModel;
using System.Threading;
using Microsoft.IdentityModel.Claims;
using OIOSaml.Serviceprovider.Headers;

namespace EchoWebserviceProvider
{
    //public class EchoService : IEchoService
    //{
    //    public Structure Echo(Structure structureToEcho)
    //    {
    //        var principal = Thread.CurrentPrincipal as ClaimsPrincipal;


    //        var str = new Structure();
    //        if (principal != null)
    //            str.value = principal.ToString();
    //        else
    //        {
    //            str.value = "null";
    //        }
    //        return str;
    //    }
    //}
    public class EchoService : IEchoService2
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

        public EchoMessage Echo(EchoMessage structureToEcho)
        {
            var reply = new EchoMessage();
            reply.structureToEcho = Echo(structureToEcho.structureToEcho);
            return reply;
        }
    }
}
