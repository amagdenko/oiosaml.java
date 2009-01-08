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

    //public class LibertyHeader : MessageHeader
    //{
    //    public override bool MustUnderstand
    //    {
    //        get
    //        {
    //            return true;
    //        }
    //    }


    //    public override string Name
    //    {
    //        get { return "Framework"; }
    //    }

    //    public override string Namespace
    //    {
    //        get { return "urn:liberty:sb:2006-08"; }
    //    }

    //    protected override void OnWriteHeaderContents(XmlDictionaryWriter writer, MessageVersion messageVersion)
    //    {
    //        writer.WriteAttributeString("version", "2.0");

    //        writer.WriteAttributeString("sbfprofile", "urn:liberty:sb:profile:basic", "urn:liberty:sb:profile");
    //    }
    //}
}
