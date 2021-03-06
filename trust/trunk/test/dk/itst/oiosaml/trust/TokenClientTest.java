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
package dk.itst.oiosaml.trust;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;

import javax.xml.bind.JAXBContext;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.namespace.QName;

import org.jmock.Expectations;
import org.jmock.api.Invocation;
import org.jmock.lib.action.CustomAction;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Detail;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Fault;
import org.opensaml.ws.soap.soap11.FaultString;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.soap.util.SOAPConstants;
import org.opensaml.ws.wsaddressing.Action;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wsaddressing.MessageID;
import org.opensaml.ws.wsaddressing.Metadata;
import org.opensaml.ws.wsaddressing.RelatesTo;
import org.opensaml.ws.wsaddressing.ReplyTo;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wstrust.Claims;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSAnyUnmarshaller;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.util.XMLHelper;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.common.SOAPException;
import dk.itst.oiosaml.liberty.ActAs;
import dk.itst.oiosaml.liberty.SecurityContext;
import dk.itst.oiosaml.liberty.Token;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.util.SOAPClient;


public class TokenClientTest extends TrustTests {

	private static final String ADDRESS = "https://oiosaml.trifork.com:8082/TokenService/services/Trust";
	private Assertion assertion;
	private EndpointReference epr;
	private BasicX509Credential credential;
	private BasicX509Credential stsCredential;
	private TrustClient client;
	private SOAPClient soapClient;

	@Before
	public void setUp() throws UnmarshallingException, CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		credential = TestHelper.getCredential();
		assertion = (Assertion)SAMLUtil.unmarshallElement(getClass().getResourceAsStream("assertion.xml"));
		epr = SAMLUtil.buildXMLObject(EndpointReference.class);
		
		Address address = SAMLUtil.buildXMLObject(Address.class);
		address.setValue(ADDRESS);
		epr.setAddress(address);
		
		Metadata md = SAMLUtil.buildXMLObject(Metadata.class);
		epr.setMetadata(md);

		SecurityContext ctx = SAMLUtil.buildXMLObject(SecurityContext.class);
		md.getUnknownXMLObjects().add(ctx);

		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().setNotOnOrAfter(new DateTime().plusMinutes(5));
		assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).setAudienceURI("tri-test1.trifork.com");
		assertion.setSignature(null);
		new OIOAssertion(assertion).sign(credential);
		
		Token token = new Token();
		token.setUsage("urn:liberty:security:tokenusage:2006-08:SecurityToken");
		ctx.getTokens().add(token);
		token.setAssertion(assertion);
		
		stsCredential = TestHelper.getCredential();
		client = new TrustClient(epr, credential, stsCredential.getPublicKey());
		soapClient = context.mock(SOAPClient.class);
		client.setSOAPClient(soapClient);
	}
	
	@Test
	public void testGetToken() throws Exception {
		client.setAppliesTo("urn:service");

		final OIOSoapEnvelope env = OIOSoapEnvelope.buildEnvelope(SOAPConstants.SOAP11_NS);
		RequestSecurityTokenResponse rstr = SAMLUtil.buildXMLObject(RequestSecurityTokenResponse.class);
		RequestedSecurityToken rdst = SAMLUtil.buildXMLObject(RequestedSecurityToken.class);
		rdst.setUnknownXMLObject(assertion);
		rstr.getUnknownXMLObjects().add(rdst);
		new OIOAssertion(assertion).sign(stsCredential);
		
		env.setBody(rstr);
		
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")));
			will(returnValue(SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(env.sign(stsCredential)))));
		}});
		
		client.setClaimsDialect("urn:testing");
		Assertion token = client.getToken();
		
		assertEquals(XMLHelper.nodeToString(SAMLUtil.marshallObject(assertion)), XMLHelper.nodeToString(token.getDOM()));
		
		OIOSoapEnvelope request = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(holder.getValue()));
		System.out.println(holder.getValue());
		assertTrue(request.isSigned());
		
		assertTrue(request.getBody() instanceof RequestSecurityToken);
		RequestSecurityToken rst = ((RequestSecurityToken)request.getBody());
		
		AppliesTo appliesTo = SAMLUtil.getFirstElement(rst, AppliesTo.class);
		ActAs obo = SAMLUtil.getFirstElement(rst, ActAs.class);
		assertEquals("urn:service", SAMLUtil.getFirstElement(appliesTo, EndpointReference.class).getAddress().getValue());
		assertEquals("pVQYCtN.5RD5VtkGJx3Fhecjrkd", ((Assertion)obo.getUnknownXMLObject()).getID());

		Claims claims = SAMLUtil.getFirstElement(rst, Claims.class);
		assertNotNull(claims);
		assertEquals("urn:testing", claims.getDialect());
	}
	
	@Test(expected=TrustException.class)
	public void testGetTokenFault() throws Exception {
		client.setAppliesTo("urn:service");

		final Envelope response = SAMLUtil.buildXMLObject(Envelope.class);
		response.setBody(SAMLUtil.buildXMLObject(Body.class));
		Fault fault = SAMLUtil.buildXMLObject(Fault.class);
		fault.setDetail(SAMLUtil.buildXMLObject(Detail.class));
		response.getBody().getUnknownXMLObjects().add(fault);
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(any(String.class)), with(equal("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue")));
			will(returnValue(response));
		}});
		
		client.getToken();
	}
	
	@Test
	public void sendRequestWithoutToken() throws Exception {
		Assertion body = SAMLUtil.buildXMLObject(Assertion.class);
		
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					return buildResponse(holder.getValue(), false);
				}
			});
		}});
		
		client.getServiceClient().sendRequest(body, ADDRESS, "urn:action", null, new ResultHandler<XMLObject>() {
			public void handleResult(XMLObject res) {
				assertTrue(res instanceof Assertion);
			}
		});
		
		OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(holder.getValue()));
		assertTrue(env.isSigned());
		assertNotNull(env.getHeaderElement(MessageID.class));
		assertNotNull(env.getHeaderElement(Action.class));
		assertNotNull(env.getHeaderElement(ReplyTo.class));
		
		Security sec = env.getHeaderElement(Security.class);
		assertNotNull(sec);
		assertNull(SAMLUtil.getFirstElement(sec, Assertion.class));
		
		assertTrue(env.verifySignature(credential.getPublicKey()));
	}

	@Test
	public void sendRequestWithSenderVouchesToken() throws Exception {
		ServiceClient client = this.client.getServiceClient();
		client.setToken(assertion);
		
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					return buildResponse(holder.getValue(), false);
				}
			});
		}});
		Assertion body = SAMLUtil.buildXMLObject(Assertion.class);
		client.sendRequest(body, ADDRESS, "urn:action", null, null);

		OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(holder.getValue()));
		assertFalse(env.isHolderOfKey());
		assertTrue(env.isSigned());
		
		Security sec = env.getHeaderElement(Security.class);
		assertNotNull(sec);
		assertNotNull(SAMLUtil.getFirstElement(sec, Assertion.class));
	} 
	
	
	@Test(expected=TrustException.class)
	public void failIfResponseIsNotSigned() throws Exception {
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					return buildResponse(holder.getValue(), false);
				}
			});
		}});
		Assertion body = SAMLUtil.buildXMLObject(Assertion.class);
		client.getServiceClient().sendRequest(body, ADDRESS, "urn:action", stsCredential.getPublicKey(), null);
	}
	
	
	@Test(expected=TrustException.class)
	public void failIfResponseIsSignedWithValidKey() throws Exception {
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					return buildResponse(holder.getValue(), false);
				}
			});
		}});
		Assertion body = SAMLUtil.buildXMLObject(Assertion.class);
		client.getServiceClient().sendRequest(body, ADDRESS, "urn:action", credential.getPublicKey(), null);
	}

	@Test
	public void testValidateResponseSignature() throws Exception {
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					return buildResponse(holder.getValue(), true);
				}
			});
		}});
		Assertion body = SAMLUtil.buildXMLObject(Assertion.class);
		client.getServiceClient().sendRequest(body, ADDRESS, "urn:action", stsCredential.getPublicKey(), null);
	}
	
	@Test
	public void testBodyAsDOMElement() throws Exception {
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					return buildResponse(holder.getValue(), true);
				}
			});
		}});
		String xml = "<test:blah xmlns:test='urn:testing'><test:more>blah</test:more></test:blah>";
		
		client.getServiceClient().sendRequest(SAMLUtil.loadElementFromString(xml), ADDRESS, "urn:action", stsCredential.getPublicKey(), null);
	}
	
	@Test
	public void testFaultHandlers() throws Exception {
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
//					System.out.println(holder.getValue());
					Envelope f = buildFault(holder.getValue());
					throw new SOAPException(500, XMLHelper.nodeToString(SAMLUtil.marshallObject(f)));
				}
			});
		}});
		String xml = "<test:blah xmlns:test='urn:testing'><test:more>blah</test:more></test:blah>";
		
		final StringValueHolder faultHolder = new StringValueHolder();
		ServiceClient client = this.client.getServiceClient();
		client.addFaultHander("urn:test", "fault", new FaultHandler() {
			public void handleFault(QName faultCode, String faultMessage, XMLObject detail) {
				assertEquals("test", faultMessage);
				assertEquals("urn:test", detail.getElementQName().getNamespaceURI());
				assertEquals("fault", detail.getElementQName().getLocalPart());
				
				faultHolder.setValue("test");
			}
		});
		
		client.sendRequest(SAMLUtil.loadElementFromString(xml), ADDRESS, "urn:action", null, null);
		assertNotNull(faultHolder.getValue());
		
	}
	
	
	@Test
	public void testJAXBRequest() throws Exception {
		final StringValueHolder holder = new StringValueHolder();
		context.checking(new Expectations() {{
			one(soapClient).wsCall(with(equal(ADDRESS)), with(aNull(String.class)), with(aNull(String.class)), with(equal(true)), with(holder), with(equal("urn:action")));
			will(new CustomAction("test") {
				public Object invoke(Invocation invocation) throws Throwable {
					OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(holder.getValue()));
					
					Envelope response = SAMLUtil.buildXMLObject(Envelope.class);
					response.setHeader(SAMLUtil.buildXMLObject(Header.class));
					RelatesTo relatesTo = SAMLUtil.buildXMLObject(RelatesTo.class);
					relatesTo.setValue(env.getMessageID());
					response.getHeader().getUnknownXMLObjects().add(relatesTo);
					
					String xml = "<test:blah xmlns:test='urn:testing'><test:more>blah</test:more></test:blah>";
					response.setBody(SAMLUtil.buildXMLObject(Body.class));
					response.getBody().getUnknownXMLObjects().add(new XSAnyUnmarshaller().unmarshall(SAMLUtil.loadElementFromString(xml)));
					return response;
				}
			});
		}});
		
		client.getServiceClient().sendRequest(new TestBean(), JAXBContext.newInstance(TestBean.class), ADDRESS, "urn:action", null, null);
	}
	
	private Envelope buildResponse(String request, boolean sign) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		OIOSoapEnvelope env = new OIOSoapEnvelope((Envelope) SAMLUtil.unmarshallElementFromString(request));
		
		Envelope response = SAMLUtil.buildXMLObject(Envelope.class);
		response.setHeader(SAMLUtil.buildXMLObject(Header.class));
		
		RelatesTo relatesTo = SAMLUtil.buildXMLObject(RelatesTo.class);
		relatesTo.setValue(env.getMessageID());
		response.getHeader().getUnknownXMLObjects().add(relatesTo);
		
		response.setBody(SAMLUtil.buildXMLObject(Body.class));
		response.getBody().getUnknownXMLObjects().add(SAMLUtil.buildXMLObject(Assertion.class));
		 
		if (sign) {
			response = (Envelope) SAMLUtil.unmarshallElementFromString(XMLHelper.nodeToString(new OIOSoapEnvelope(response, true, new SigningPolicy(true)).sign(stsCredential)));
		}
		
		return response;
	}
	
	public Envelope buildFault(String request) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {
		Envelope r = buildResponse(request, false);
		r.getBody().getUnknownXMLObjects().clear();
		
		Fault fault = SAMLUtil.buildXMLObject(Fault.class);
		Detail detail = SAMLUtil.buildXMLObject(Detail.class);

		FaultString msg = SAMLUtil.buildXMLObject(FaultString.class);
		msg.setValue("test");
		fault.setMessage(msg);
		
		fault.setDetail(detail);

		XSAny d = new XSAnyBuilder().buildObject("urn:test", "fault", "fa");
		detail.getUnknownXMLObjects().add(d);
		
		r.getBody().getUnknownXMLObjects().add(fault);
		
		return r;
	}
	
}
