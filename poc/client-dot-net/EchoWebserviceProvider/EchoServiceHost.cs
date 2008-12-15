using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;

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