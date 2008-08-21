/*
 * The contents of this file are subject to the Mozilla Public 
 * License Version 1.1 (the "License"); you may not use this 
 * file except in compliance with the License. You may obtain 
 * a copy of the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, either express 
 * or implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 *
 * The Original Code is OIOSAML Authz
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
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

class Utils {
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
