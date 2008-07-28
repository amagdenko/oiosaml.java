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
 * The Original Code is OIOSAML Java Service Provider.
 * 
 * The Initial Developer of the Original Code is Trifork A/S. Portions 
 * created by Trifork A/S are Copyright (C) 2008 Danish National IT 
 * and Telecom Agency (http://www.itst.dk). All Rights Reserved.
 * 
 * Contributor(s):
 *   Joakim Recht <jre@trifork.com>
 *   Rolf Njor Jensen <rolf@trifork.com>
 *
 */
package dk.itst.oiosaml.sp.model;

import java.security.PublicKey;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.validation.ValidationException;

import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.logging.LogUtil;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.sp.service.util.Utils;
import dk.itst.oiosaml.sp.util.BRSUtil;

public class OIOLogoutResponse extends OIOAbstractResponse {
	private static final Logger log = Logger.getLogger(OIOLogoutResponse.class);

	private final LogoutResponse response;

	public OIOLogoutResponse(LogoutResponse response) {
		super(response);
		this.response = response;
	}
	
	public static OIOLogoutResponse fromRequest(OIOLogoutRequest request, String statusCode, String consent, String entityId, String destination) {
		LogoutResponse logoutResponse = BRSUtil.buildXMLObject(LogoutResponse.class);

		logoutResponse.setID(Utils.generateUUID());
		logoutResponse.setIssueInstant(new DateTime(DateTimeZone.UTC));
		logoutResponse.setVersion(SAMLVersion.VERSION_20);
		logoutResponse.setStatus(BRSUtil.createStatus(statusCode != null ? statusCode : StatusCode.SUCCESS_URI));
		
		if (request != null) {
			logoutResponse.setInResponseTo(request.getID());
		}
		logoutResponse.setIssuer(BRSUtil.createIssuer(entityId));
		logoutResponse.setDestination(destination);
		if (consent != null) {
			logoutResponse.setConsent(consent);
		}
		if (statusCode != null && statusCode != StatusCode.SUCCESS_URI) {
			log.error("Invalid <LogoutRequest>: " + consent);
		}
		try {
			if (log.isDebugEnabled()) log.debug("Validate the logoutResponse...");
			logoutResponse.validate(true);
			if (log.isDebugEnabled()) log.debug("...OK");
		} catch (ValidationException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		return new OIOLogoutResponse(logoutResponse);
	}
	
	public static OIOLogoutResponse fromHttpRedirect(HttpServletRequest request) {
		BasicSAMLMessageContext<LogoutResponse, ?, ?> messageContext = new BasicSAMLMessageContext<LogoutResponse, SAMLObject, SAMLObject>();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));


		try {
			HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
			decoder.decode(messageContext);
		} catch (MessageDecodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		} catch (SecurityException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}

		LogoutResponse logoutResponse = messageContext.getInboundSAMLMessage();
		
		OIOLogoutResponse res = new OIOLogoutResponse(logoutResponse);
		if (log.isDebugEnabled()) log.debug("Received response: " + res.toXML());
		
		return res;
	}
	
	/**
	 * @param relayState
	 *            The relayState to be included with the &lt;LogoutResponse&gt;
	 * @return A URL containing an &lt;LogoutResponse&gt; as a response to a
	 *         &lt;LogoutRequest&gt;
	 */
	public String getRedirectURL(Credential signingCredential, String relayState, LogUtil lu) {
		
		// Build the <LogoutResponse>
		lu.setRequestId(response.getID());
		lu.audit(Constants.SERVICE_LOGOUT_REQUEST, toXML());

		Encoder enc = new Encoder();

		// Build the parameters for the response
		if (log.isDebugEnabled())
			log.debug("Setting RelayState..:" + relayState);

		try {
			return buildRedirectURL(enc.deflateAndBase64Encode(response), relayState, signingCredential);
		} catch (MessageEncodingException e) {
			throw new WrappedException(Layer.CLIENT, e);
		}
	}

	/**
	 * @see org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder#buildRedirectURL(org.opensaml.common.binding.SAMLMessageContext,
	 *      java.lang.String, java.lang.String)
	 */
	private String buildRedirectURL(String message, String relayState, Credential signingCredential) throws MessageEncodingException {

		if (log.isDebugEnabled())
			log.debug("Building URL to redirect client to: " + response.getDestination());

		URLBuilder urlBuilder = new URLBuilder(response.getDestination());

		List<Pair<String, String>> queryParams = urlBuilder.getQueryParams();
		queryParams.clear();
		queryParams.add(new Pair<String, String>(Constants.SAML_SAMLRESPONSE, message));

		queryParams.add(new Pair<String, String>(Constants.SAML_RELAYSTATE, relayState));

		Encoder enc = new Encoder();
		if (signingCredential != null) {
			queryParams.add(new Pair<String, String>(Constants.SAML_SIGALG, enc.getSignatureAlgorithmURI(signingCredential, null)));
			String sigMaterial = urlBuilder.buildQueryString();

			queryParams.add(new Pair<String, String>(Constants.SAML_SIGNATURE,
					enc.generateSignature(signingCredential, enc.getSignatureAlgorithmURI(signingCredential, null), sigMaterial)));
		}
		return urlBuilder.buildURL();
	}
	
	public void validate(String requestId, String expectedDestination) throws dk.itst.oiosaml.error.ValidationException {
		try {
			response.validate(true);
		} catch (ValidationException e) {
			log.error("Unable to validate message", e);
			throw new dk.itst.oiosaml.error.ValidationException(e);
		}
		validateResponse(requestId, expectedDestination, false);
	}
	
	public void validate(String requestId, String expectedDestination, String signature, String queryString, PublicKey key) {
		validate(requestId, expectedDestination);
		// Verifying the signature....
		if (!Utils.verifySignature(signature, queryString, Constants.SAML_SAMLRESPONSE, key)) {
			throw new dk.itst.oiosaml.error.ValidationException("Invalid signature");
		} else if (log.isDebugEnabled()) {
			log.debug("...signature OK");
		}

	}
	
	protected class Encoder extends HTTPRedirectDeflateEncoder {
		
		@Override
		public String deflateAndBase64Encode(SAMLObject obj) throws MessageEncodingException {
			return super.deflateAndBase64Encode(obj);
		}
		
		@Override
		public String getSignatureAlgorithmURI(Credential arg0, SecurityConfiguration arg1) throws MessageEncodingException {
			return super.getSignatureAlgorithmURI(arg0, arg1);
		}
		
		@Override
		public String generateSignature(Credential arg0, String arg1, String arg2) throws MessageEncodingException {
			return super.generateSignature(arg0, arg1, arg2);
		}
	}
}
