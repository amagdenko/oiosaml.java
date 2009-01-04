using System.Runtime.Serialization;

namespace EchoWebserviceProvider
{
    [DataContract(Namespace = "http://provider.poc.saml.itst.dk/")]
    public partial class Structure
    {

        private Structure[] structureField;

        private string valueField;

        /// <remarks/>
        [DataMember(Name = "structure", Order = 0)]
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
        [DataMember(Order = 1)]
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