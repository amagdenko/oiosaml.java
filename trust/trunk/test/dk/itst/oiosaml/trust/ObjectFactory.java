
package dk.itst.oiosaml.trust;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


@XmlRegistry
public class ObjectFactory {

    private final static QName _Test_QNAME = new QName("urn:testing", "test");

    public TestBean createTestBean() {
        return new TestBean();
    }

    @XmlElementDecl(namespace = "urn:testing", name = "blah")
    public JAXBElement<TestBean> createTestBean(TestBean value) {
        return new JAXBElement<TestBean>(_Test_QNAME, TestBean.class, null, value);
    }

}
