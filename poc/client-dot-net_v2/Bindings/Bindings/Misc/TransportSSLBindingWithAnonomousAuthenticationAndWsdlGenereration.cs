using System.Net;
using System.ServiceModel.Channels;

namespace OIOSaml.Serviceprovider.Binding.Misc
{
    /// <summary>
    /// ASymmetricSecurityBindingElement and HttpsTransportbindingelement is not supported, and disables wsdl generation for the service. 
    /// As well as excludes the possibility to have multiple endpoints listening for the same  service.
    /// This overwrites the above behaviour and enables ssl and wdsl generation.
    /// </summary>
    public class TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration : HttpTransportBindingElement
    {
        public TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration()
        {
            this.AuthenticationScheme = AuthenticationSchemes.Anonymous;
            this.ProxyAuthenticationScheme = AuthenticationSchemes.Anonymous;
        }
        public TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration(TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration other)
            : base(other)
        {
            this.AuthenticationScheme = AuthenticationSchemes.Anonymous;
            this.ProxyAuthenticationScheme = AuthenticationSchemes.Anonymous;
        }

        public override BindingElement Clone()
        {
            return new TransportSSLBindingWithAnonomousAuthenticationAndWsdlGenereration(this);
        }

        public override string Scheme
        {
            get { return "https"; }
        }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            HttpsTransportBindingElement ele = new HttpsTransportBindingElement();
            return ele.BuildChannelFactory<TChannel>(context);
        }
        public override IChannelListener<TChannel> BuildChannelListener<TChannel>(BindingContext context)
        {
            HttpsTransportBindingElement ele = new HttpsTransportBindingElement();
            return ele.BuildChannelListener<TChannel>(context);
        }
    }
}
