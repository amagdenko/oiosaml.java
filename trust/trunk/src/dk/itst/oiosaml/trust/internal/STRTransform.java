/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package dk.itst.oiosaml.trust.internal;

import java.io.IOException;
import java.io.OutputStream;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.log4j.Logger;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.Reference;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.ws.wssecurity.impl.SecurityTokenReferenceUnmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import dk.itst.oiosaml.common.SAMLUtil;

/**
 * Class STRTransform
 * 
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 * @version 1.0
 */
public class STRTransform extends TransformSpi {

	/**
	 * Field implementedTransformURI
	 */
	public static final String implementedTransformURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";

	private static Logger log = Logger.getLogger(STRTransform.class);

	private static boolean doDebug = false;

	/**
	 * Method engineGetURI
	 */
	protected String engineGetURI() {
		return STRTransform.implementedTransformURI;
	}

	/**
	 * Method enginePerformTransform
	 * 
	 * @param input
	 * @throws CanonicalizationException
	 * @throws InvalidCanonicalizerException
	 */
	protected XMLSignatureInput enginePerformTransform(XMLSignatureInput input, OutputStream os, Transform _transformObject) throws IOException, CanonicalizationException, InvalidCanonicalizerException {

		doDebug = log.isDebugEnabled();

		if (doDebug) {
			log.debug("Beginning STRTransform..." + input.toString());
		}

		/*
		 * Get the main document, that is the complete SOAP request document
		 */
		Document thisDoc = _transformObject.getDocument();
		int docHash = thisDoc.hashCode();
		if (doDebug) {
			log.debug("doc: " + thisDoc.toString() + ", " + docHash);
		}

		/*
		 * According to the OASIS WS Specification "Web Services Security:
		 * SOAP Message Security 1.0" Monday, 19 January 2004, chapter 8.3
		 * describes that the input node set must be processed bythe c14n
		 * that is specified in the argument element of the STRTransform
		 * element.
		 * 
		 * First step: Get the required c14n argument and get the specified
		 * Canonicalizer
		 */

		String canonAlgo = null;
		if (_transformObject.length(WSSecurityConstants.WSSE_NS,
		"TransformationParameters") == 1) {
			Element tmpE = XMLUtils.selectNode(_transformObject
					.getElement().getFirstChild(), WSSecurityConstants.WSSE_NS,
					"TransformationParameters", 0);
			Element canonElem = (Element) XMLHelper.getChildElementsByTagNameNS(tmpE, XMLSignature.XMLNS, "CanonicalizationMethod").get(0); 
			canonAlgo = canonElem.getAttribute("Algorithm");
			if (doDebug) {
				log.debug("CanonAlgo: " + canonAlgo);
			}
		}
		Canonicalizer canon = Canonicalizer.getInstance(canonAlgo);

		if (doDebug) {
			log.debug("canon bos: " + new String(input.getBytes()));
		}

		/*
		 * Get the input (node) to transform. Currently we support only an
		 * Element as input format. If other formats are required we must
		 * get it as bytes and probably reparse it into a DOM tree (How to
		 * work with nodesets? how to select the right node from a nodeset?)
		 */
		Element str = null;
		if (input.isElement()) {
			str = (Element) input.getSubNode();
		} else {
			throw (new CanonicalizationException(
					"Wrong input format - only element input supported"));
		}

		if (doDebug) {
			log.debug("STR: " + str);
		}
		/*
		 * The element to transform MUST be a SecurityTokenReference
		 * element.
		 */
		SecurityTokenReference secRef;
		try {
			secRef = (SecurityTokenReference) new SecurityTokenReferenceUnmarshaller().unmarshall(str);
		} catch (UnmarshallingException e) {
			throw new CanonicalizationException("Unable to handle token reference", e);
		}
		if (doDebug) {
			log.debug("STR: " + secRef);
		}
		/*
		 * Third and forth step are performed by derefenceSTR()
		 */
		Element dereferencedToken = dereferenceSTR(thisDoc, secRef);
		/*
		 * C14n with specified algorithm. According to WSS Specification.
		 */
		if (os != null) {
			canon.setWriter(os);
		}
		byte[] buf = canon.canonicalizeSubtree(dereferencedToken);

		XMLSignatureInput result = new XMLSignatureInput(buf);
		if (os != null) {
			input.setOutputStream(os);
		}
		return result;
	}

	private Element dereferenceSTR(Document doc, SecurityTokenReference secRef) throws CanonicalizationException {
		String id = null;
		KeyIdentifier keyIdentifier = SAMLUtil.getFirstElement(secRef, KeyIdentifier.class);
		Reference ref = SAMLUtil.getFirstElement(secRef, Reference.class);
		if (keyIdentifier != null) {
			id = keyIdentifier.getValue();
		} else if (ref != null) {
			id = ref.getURI().substring(1);
		}
		Element token = doc.getElementById(id);
		if (token == null) {
			establishIdness(doc);
			token = doc.getElementById(id);
		}
		if (doDebug) {
			log.debug("Referenced token with id " + id + ": " + token);
		}
		if (token == null) {
			throw new CanonicalizationException("Token with id " + id + " not found");
		}
		return token;

	}

	private void establishIdness(Document doc) {
		NodeList nl = doc.getElementsByTagNameNS("*", "*");
		for (int i = 0; i < nl.getLength(); i++) {
    		Element e = (Element) nl.item(i);
    		if (e.hasAttribute("ID")) {
    			e.setIdAttributeNS(null, "ID", true);
    		}
    		if (e.hasAttributeNS(WSSecurityConstants.WSU_NS, "Id")) {
    			e.setIdAttributeNS(WSSecurityConstants.WSU_NS, "Id", true);
    		}
		}
	}

}
