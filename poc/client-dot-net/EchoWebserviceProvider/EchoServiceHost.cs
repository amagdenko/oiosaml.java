using System;
using System.ServiceModel;

namespace EchoWebserviceProvider
{
    internal class EchoServiceHost : ServiceHost
    {
        #region EchoServiceHost Constructor
        public EchoServiceHost(params Uri[] addresses)
            : base(typeof(EchoService), addresses)
        {
        }
        #endregion
    }

}