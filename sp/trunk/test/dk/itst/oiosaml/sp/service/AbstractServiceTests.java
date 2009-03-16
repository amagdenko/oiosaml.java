package dk.itst.oiosaml.sp.service;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jmock.Expectations;
import org.junit.Before;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.security.credential.Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.AbstractTests;
import dk.itst.oiosaml.sp.bindings.BindingHandlerFactory;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.SPMetadata;
import dk.itst.oiosaml.sp.model.OIOAssertion;
import dk.itst.oiosaml.sp.service.session.SessionHandler;
import dk.itst.oiosaml.sp.service.session.SessionHandlerFactory;
import dk.itst.oiosaml.sp.service.session.SingleVMSessionHandlerFactory;
import dk.itst.oiosaml.sp.service.util.Constants;

public abstract class AbstractServiceTests extends AbstractTests {

	protected HttpServletRequest req;
	protected HttpServletResponse res;
	protected HttpSession session;
	protected Assertion assertion;
	protected SessionHandler handler;

	protected Credential credential;
	protected IdpMetadata idpMetadata;
	protected SPMetadata spMetadata;

	protected String idpEntityId;
	
	protected CredentialRepository credentialRepository = new CredentialRepository();
	protected SessionHandlerFactory handlerFactory;
	protected BindingHandlerFactory bindingHandlerFactory;

	@Before
	public void setUpTests() throws Exception {
		bindingHandlerFactory = context.mock(BindingHandlerFactory.class);

		credential = TestHelper.getCredential();
		req = context.mock(HttpServletRequest.class);
		res = context.mock(HttpServletResponse.class);
		session = context.mock(HttpSession.class);
		context.checking(new Expectations() {{
			allowing(session).getId(); will(returnValue("" + System.currentTimeMillis()));
			allowing(req).getSession(); will(returnValue(session));
		}});
		assertion = (Assertion) SAMLUtil.unmarshallElement(getClass().getResourceAsStream("/dk/itst/oiosaml/sp/model/assertion.xml"));

		handlerFactory = SessionHandlerFactory.Factory.newInstance(TestHelper.buildConfiguration(new HashMap<String, String>() {{ put(Constants.PROP_SESSION_HANDLER_FACTORY, SingleVMSessionHandlerFactory.class.getName()); }}));
		handler = handlerFactory.getHandler();
		handler.resetReplayProtection(10);
		
		idpMetadata = new IdpMetadata(SAMLConstants.SAML20P_NS, TestHelper.buildEntityDescriptor(credential));
		spMetadata = TestHelper.buildSPMetadata();
		idpEntityId = idpMetadata.getEntityIDs().iterator().next();
	}


	protected void setHandler() {
		handler.setAssertion(session.getId(), new OIOAssertion(assertion));
	}

}
