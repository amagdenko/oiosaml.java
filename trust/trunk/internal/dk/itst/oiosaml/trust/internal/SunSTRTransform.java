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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.ws.wssecurity.impl.SecurityTokenReferenceUnmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.c14n.InvalidCanonicalizerException;
import com.sun.org.apache.xml.internal.security.signature.XMLSignatureInput;
import com.sun.org.apache.xml.internal.security.transforms.TransformSpi;

/**
 * Class STRTransform
 * 
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 * @version 1.0
 */
public class SunSTRTransform extends TransformSpi {

    /**
     * Field implementedTransformURI
     */
    public static final String implementedTransformURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";

    private static Log log = LogFactory.getLog(SunSTRTransform.class.getName());

    private static boolean doDebug = false;

    private static String XMLNS = "xmlns=";

    public boolean wantsOctetStream() {
        return false;
    }

    public boolean wantsNodeSet() {
        return true;
    }

    public boolean returnsOctetStream() {
        return true;
    }

    public boolean returnsNodeSet() {
        return false;
    }

    /**
     * Method engineGetURI
     */
    protected String engineGetURI() {
        return SunSTRTransform.implementedTransformURI;
    }

    /**
     * Method enginePerformTransform
     * 
     * @param input
     * @throws CanonicalizationException
     * @throws InvalidCanonicalizerException
     */
    protected XMLSignatureInput enginePerformTransform(XMLSignatureInput input)
            throws IOException, CanonicalizationException,
            InvalidCanonicalizerException {

        doDebug = log.isDebugEnabled();

        if (doDebug) {
            log.debug("Beginning STRTransform..." + input.toString());
        }

            /*
             * Get the main document, that is the complete SOAP request document
             */
            Document thisDoc = this._transformObject.getDocument();
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
            if (this._transformObject.length(WSSecurityConstants.WSSE_NS,
                    "TransformationParameters") == 1) {
                Element tmpE = XMLUtils.selectNode(this._transformObject
                        .getElement().getFirstChild(), WSSecurityConstants.WSSE_NS,
                        "TransformationParameters", 0);
                Element canonElem = (Element) XMLHelper.getChildElementsByTagNameNS(tmpE, XMLSignature.XMLNS, "CanonicalizationMethod").get(0); 
                canonAlgo = canonElem.getAttribute("Algorithm");
                if (doDebug) {
                    log.debug("CanonAlgo: " + canonAlgo);
                }
            }
            Canonicalizer canon = Canonicalizer.getInstance(canonAlgo);

            ByteArrayOutputStream bos = null;
            byte[] buf = null;
            if (doDebug) {
                buf = input.getBytes();
                bos = new ByteArrayOutputStream(buf.length);
                bos.write(buf, 0, buf.length);
                log.debug("canon bos: " + bos.toString());
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
                log.debug("STR: " + str.toString());
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
            buf = canon.canonicalizeSubtree(dereferencedToken, "#default");
            if (doDebug) {
                bos = new ByteArrayOutputStream(buf.length);
                bos.write(buf, 0, buf.length);
                log.debug("after c14n: " + bos.toString());
            }

            if (true) 
            return new XMLSignatureInput(buf);
            /*
             * Alert: Hacks ahead According to WSS spec an Apex node must
             * contain a default namespace. If none is availabe in the first
             * node of the c14n output (this is the apex element) then we do
             * some editing to insert an empty default namespace
             * 
             * TODO: Rework theses hacks after c14n was updated and can be
             * instructed to insert empty default namespace if required
             */
            // If the problem with c14n method is solved then just do:
            
            // start of HACK
            StringBuffer bf = new StringBuffer(new String(buf));
            String bf1 = bf.toString();

            /*
             * Find start and end of first element <....>, this is the Apex node
             */
            int gt = bf1.indexOf(">");
            /*
             * Lookup the default namespace
             */
            int idx = bf1.indexOf(XMLNS);
            /*
             * If none found or if it is outside of this (Apex) element look for
             * first blank in, insert default namespace there (this is the
             * correct place according to c14n specification)
             */
            if (idx < 0 || idx > gt) {
                idx = bf1.indexOf(" ");
                bf.insert(idx + 1, "xmlns=\"\" ");
                bf1 = bf.toString();
            }
            if (doDebug) {
                log.debug("last result: " + bf1);
            }
            return new XMLSignatureInput(bf1.getBytes());
        // End of HACK
    }

    private Element dereferenceSTR(Document doc, SecurityTokenReference secRef) throws CanonicalizationException {

        /*
         * First case: direct reference, according to chap 7.2 of OASIS WS
         * specification (main document). Only in this case return a true
         * reference to the BST. Copying is done by the caller.
         */
    	String id = null;
    	if (secRef.getKeyIdentifier() != null) {
        	id = secRef.getKeyIdentifier().getValue();
        } else if (secRef.getReference() != null) {
        	id = secRef.getReference().getURI().substring(1);
        }
    	Element token = doc.getElementById(id);
    	if (doDebug) {
    		log.debug("Referenced token: " + token);
    	}
    	if (token == null) {
    		throw new CanonicalizationException("Token with id " + id + " not found");
    	}
		return token;
        
    }

}
