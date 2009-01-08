using System.Xml.Serialization;

namespace EchoWebserviceprovider.Interfaces
{
    [System.Serializable]
    public  class   Structure
    {

        private Structure[] structureField;

        private string valueField;

        /// <remarks/>
        [XmlElement(ElementName = "structure", Order = 0)]
        public Structure[] structure
        {
            get
            {
                return this.structureField;
            }
            set
            {
                this.structureField = value;
            }
        }

        /// <remarks/>
        [XmlElement(Order = 1)]
        public string value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }
}