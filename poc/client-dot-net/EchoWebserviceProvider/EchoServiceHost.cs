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
            this.CloseTimeout = new TimeSpan(0,0,5,0);
        }
        #endregion
    }

}