using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;

namespace Bindings.Data
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
