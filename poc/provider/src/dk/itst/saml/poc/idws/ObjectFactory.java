
package dk.itst.saml.poc.idws;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the liberty.sb._2006_08 package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _Framework_QNAME = new QName("urn:liberty:sb:2006-08", "Framework");
    private final static QName _UserInteraction_QNAME = new QName("urn:liberty:sb:2006-08", "UserInteraction");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: liberty.sb._2006_08
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link Framework }
     * 
     */
    public Framework createFramework() {
        return new Framework();
    }

    /**
     * Create an instance of {@link UserInteraction }
     * 
     */
    public UserInteraction createUserInteraction() {
        return new UserInteraction();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Framework }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:liberty:sb:2006-08", name = "Framework")
    public JAXBElement<Framework> createFramework(Framework value) {
        return new JAXBElement<Framework>(_Framework_QNAME, Framework.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link UserInteraction }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:liberty:sb:2006-08", name = "UserInteraction")
    public JAXBElement<UserInteraction> createUserInteraction(UserInteraction value) {
        return new JAXBElement<UserInteraction>(_UserInteraction_QNAME, UserInteraction.class, null, value);
    }

}
