using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Xml;

namespace OIOSaml.Serviceprovider.Headers
{
    [System.Serializable]
    public class LibertyFrameworkHeader
    {
        private string version;
        private string sbfprofile;

        public LibertyFrameworkHeader()
        {
            version = "2.0";
        
            sbfprofile = "urn:liberty:sb:profile:basic";
        }

        [System.Xml.Serialization.XmlAttribute(AttributeName = "version")]
        public string Version
        {
            get { return version; }
            set { version = value; }
        }

        [System.Xml.Serialization.XmlAttribute(AttributeName = "profile", Namespace = "urn:liberty:sb:profile")]
        public string Profile
        {
            get { return sbfprofile; }
            set { sbfprofile = value; }
        }
    }
}
