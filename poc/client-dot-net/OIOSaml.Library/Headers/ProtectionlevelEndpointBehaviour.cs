using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace OIOSaml.Serviceprovider.Headers
{
    //public class ProtectionLevelEndpointBehavior : IEndpointBehavior
    //{
    //    public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
    //    {

    //        ChannelProtectionRequirements requirements = bindingParameters.Find<ChannelProtectionRequirements>();
    //        MessagePartSpecification targetIdentityPart =
    //        new MessagePartSpecification(new XmlQualifiedName("Framework", "urn:liberty:sb:2006-08"));
    //        requirements.IncomingSignatureParts.AddParts(targetIdentityPart);
    //        requirements.OutgoingSignatureParts.AddParts(targetIdentityPart);
    //    }

    //    public void Validate(ServiceEndpoint endpoint)
    //    {
    //    }



    //    public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
    //    {
    //        endpointDispatcher.DispatchRuntime.MessageInspectors.Add(new DispatchBehaviour());
    //    }

    //    public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
    //    {
    //        clientRuntime.MessageInspectors.Add(new LibertyHeaderInpector());
    //    }
    //}

    //internal class DispatchBehaviour : IDispatchMessageInspector
    //{
    //    public object AfterReceiveRequest(ref Message request, IClientChannel channel, InstanceContext instanceContext)
    //    {
    //        bool libertyHeaderFound = false;

    //        foreach (var info in request.Headers)
    //        {
    //            if (info.Namespace == "urn:liberty:sb:2006-08")
    //            {
    //                libertyHeaderFound = true;
    //            }
    //        }
    //        return null;
    //    }

    //    public void BeforeSendReply(ref Message reply, object correlationState)
    //    {
    //        reply.Headers.Add(new LibertyHeader());
    //    }
    //}

    //internal class LibertyHeaderInpector : IClientMessageInspector
    //{
    //    public object BeforeSendRequest(ref Message request, IClientChannel channel)
    //    {
    //        request.Headers.Add(new LibertyHeader());
    //        return null;
    //    }

    //    public void AfterReceiveReply(ref Message reply, object correlationState)
    //    {
    //        bool libertyHeaderFound = false;
    //        foreach (var info in reply.Headers)
    //        {
    //            if (info.Namespace == "urn:liberty:sb:2006-08")
    //            {
    //                libertyHeaderFound = true;
    //                LibertyHeader libertyHeader = (LibertyHeader)info;

    //            }
    //        }

    //    }
    //}
}
