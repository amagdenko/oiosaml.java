using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading;
using EchoWebserviceprovider.Interfaces;
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
        public echoResponse Echo(echo echoRequest)
        {
            if (echoRequest.Framework == null)
            {
                MessageFault fault = MessageFault.CreateFault(FaultCode.CreateSenderFaultCode("dsvs", "cds"), new FaultReason(""));
                throw new FaultException("Missing LibertyHeader", new FaultCode("FrameworkVersionMismatch", "urn:liberty:sb:2006-08"));
            }
            if (echoRequest.Framework.Sbfprofile != "urn:liberty:sb:profile")
            {
                throw new FaultException(new FaultReason("Wrong profile"), new FaultCode("FrameworkVersionMismatch", "urn:liberty:sb:2006-08"));
            }

            var reply = new echoResponse();
            reply.structureToEcho = Echo(echoRequest.structureToEcho);
            reply.Framework = new LibertyFrameworkHeader();
            return reply;
        }

        private Structure Echo(Structure structureToEcho)
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
