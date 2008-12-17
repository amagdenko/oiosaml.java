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
 * The Original Code is OIOSAML Trust Client.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *
 */
package dk.itst.oiosaml.trust.internal;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.jcp.xml.dsig.internal.dom.DOMTransform;

@SuppressWarnings("unchecked")
public class DOMXMLSignatureFactory  extends XMLSignatureFactory {

	public URIDereferencer getURIDereferencer() {
		throw new UnsupportedOperationException();
	}

	public boolean isFeatureSupported(String feature) {
		throw new UnsupportedOperationException();
	}

	public CanonicalizationMethod newCanonicalizationMethod(String algorithm,
			C14NMethodParameterSpec params) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		throw new UnsupportedOperationException();
	}

	public CanonicalizationMethod newCanonicalizationMethod(String algorithm,
			XMLStructure params) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		throw new UnsupportedOperationException();
	}

	public DigestMethod newDigestMethod(String algorithm,
			DigestMethodParameterSpec params) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		throw new UnsupportedOperationException();
	}

	public Manifest newManifest(List references) {
		throw new UnsupportedOperationException();
	}

	public Manifest newManifest(List references, String id) {
		throw new UnsupportedOperationException();
	}

	public Reference newReference(String uri, DigestMethod dm) {
		throw new UnsupportedOperationException();
	}

	public Reference newReference(String uri, DigestMethod dm, List transforms, String type, String id) {
		throw new UnsupportedOperationException();
	}

	public Reference newReference(String uri, DigestMethod dm, List transforms, String type, String id, byte[] digestValue) {
		throw new UnsupportedOperationException();
	}

	public Reference newReference(String uri, DigestMethod dm, List appliedTransforms, Data result, List transforms, String type, String id) {
		throw new UnsupportedOperationException();
	}

	public SignatureMethod newSignatureMethod(String algorithm, SignatureMethodParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		throw new UnsupportedOperationException();
	}

	public SignatureProperties newSignatureProperties(List properties, String id) {
		throw new UnsupportedOperationException();
	}

	public SignatureProperty newSignatureProperty(List content, String target, String id) {
		throw new UnsupportedOperationException();
	}

	public SignedInfo newSignedInfo(CanonicalizationMethod cm, SignatureMethod sm, List references) {
		throw new UnsupportedOperationException();
	}

	public SignedInfo newSignedInfo(CanonicalizationMethod cm, SignatureMethod sm, List references, String id) {
		throw new UnsupportedOperationException();
	}

	public Transform newTransform(String algorithm, TransformParameterSpec params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		throw new UnsupportedOperationException();
	}

	public Transform newTransform(String algorithm, XMLStructure params) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		TransformService spi;
		try {
		    spi = TransformService.getInstance(algorithm, "DOM");
		} catch (NoSuchAlgorithmException nsae) {
		    spi = TransformService.getInstance(algorithm, "DOM", getProvider());
		}
		if (params == null) {
		    spi.init(null);
		} else {
		    spi.init(params, null);
		}
		return new DOMTransform(spi);
	}

	public XMLObject newXMLObject(List content, String id, String mimeType, String encoding) {
		throw new UnsupportedOperationException();
	}

	public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki) {
		throw new UnsupportedOperationException();
	}

	public XMLSignature newXMLSignature(SignedInfo si, KeyInfo ki, List objects, String id, String signatureValueId) {
		throw new UnsupportedOperationException();
	}

	public XMLSignature unmarshalXMLSignature(XMLValidateContext context) throws MarshalException {
		throw new UnsupportedOperationException();
	}

	public XMLSignature unmarshalXMLSignature(XMLStructure xmlStructure) throws MarshalException {
		throw new UnsupportedOperationException();
	}

}
