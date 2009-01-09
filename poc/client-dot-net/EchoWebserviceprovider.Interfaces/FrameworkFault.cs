using System.Runtime.Serialization;

namespace EchoWebserviceprovider.Interfaces
{
    [DataContract]
    public class FrameworkFault
    {
        public FrameworkFault()
        {
        }
        public FrameworkFault(string error)
        {
            Details = error;
        }
        [DataMember]
        public string Details { get; set; }
    }
}