package dk.itst.oiosaml.authz;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

public class Utils {
	private Utils() {}

	public static Element parse(String xml, String schemaFile) {
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		
		DocumentBuilderFactory bf = DocumentBuilderFactory.newInstance();
		bf.setNamespaceAware(true);
		try {
			Schema schema = sf.newSchema(Utils.class.getResource(schemaFile));
			bf.setSchema(schema);
			
			DocumentBuilder builder = bf.newDocumentBuilder();
			builder.setErrorHandler(new ErrorHandler() {
				public void error(SAXParseException exception) throws SAXException {
					throw exception;
				}

				public void fatalError(SAXParseException exception) throws SAXException {
					throw exception;
				}

				public void warning(SAXParseException exception) throws SAXException {
					throw exception;
				}
			});
			Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
			
			return doc.getDocumentElement();
		} catch (ParserConfigurationException e) {
			throw new IllegalFormatException("Unable to parse authorisations", e);
		} catch (SAXException e) {
			throw new IllegalFormatException("Unable to parse authorisations", e);
		} catch (IOException e) {
			throw new IllegalFormatException("Unable to parse authorisations", e);
		}
	}
	
	public static void checkNotNull(Object o, String name) {
		if (o == null) {
			throw new IllegalArgumentException("Argument " + name + " cannot be null");
		}
	}
}
