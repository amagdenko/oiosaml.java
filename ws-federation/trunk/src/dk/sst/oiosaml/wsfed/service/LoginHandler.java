package dk.sst.oiosaml.wsfed.service;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.GregorianCalendar;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.Endpoint;

import dk.itst.oiosaml.sp.UserAssertionHolder;
import dk.itst.oiosaml.sp.metadata.IdpMetadata;
import dk.itst.oiosaml.sp.metadata.IdpMetadata.Metadata;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.SAMLHandler;
import dk.itst.oiosaml.sp.service.util.Constants;
import dk.itst.oiosaml.trust.TrustBootstrap;

public class LoginHandler implements SAMLHandler {
	
	private static final Logger log = Logger.getLogger(LoginHandler.class);
	
	static {
		TrustBootstrap.bootstrap();
	}

	public void handleGet(RequestContext context) throws ServletException, IOException {
		IdpMetadata idpMetadata = context.getIdpMetadata();
		
		try {
			XMLGregorianCalendar cal = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());
		
		Metadata metadata = idpMetadata.getFirstMetadata();
		
		Endpoint loginEndpoint = metadata.findLoginEndpoint(new String[] {"http://schemas.xmlsoap.org/ws/2006/12/federation"});
		log.debug("Signing on at " + loginEndpoint.getLocation());
		
		HttpSession session = context.getSession();
		session.removeAttribute(Constants.SESSION_USER_ASSERTION);
		UserAssertionHolder.set(null);
		
		String relayState = context.getRequest().getParameter(Constants.SAML_RELAYSTATE);
		
		boolean useRedirect = true;
		
//		String xml = XMLHelper.nodeToString(SAMLUtil.marshallObject(req.getXMLObject()));
		if (useRedirect) {
			StringBuilder sb = new StringBuilder(loginEndpoint.getLocation());
			sb.append("?wa=wsignin1.0");
			sb.append("&wctx=").append(relayState);
			sb.append("&wtrealm=").append(URLEncoder.encode(context.getSpMetadata().getEntityID(), "UTF-8"));
			sb.append("&wreply=").append(URLEncoder.encode(context.getSpMetadata().getDefaultAssertionConsumerService().getLocation(), "UTF-8"));
			sb.append("&wct=" + URLEncoder.encode(cal.toXMLFormat(), "UTF-8"));
//			sb.append("&wreq=").append(URLEncoder.encode(xml, "UTF-8"));
			
			context.getResponse().sendRedirect(sb.toString());
		} else {
//			xml = xml.replaceAll("&", "&amp;");
//			xml = xml.replaceAll("\"", "&quot;");
//			xml = xml.replaceAll("<", "&lt;");
//			xml = xml.replaceAll(">", "&gt;");
//			
//			VelocityContext vc = new VelocityContext();
//			vc.put("action", loginEndpoint.getLocation());
//
//			Map<String, String> params = new HashMap<String, String>();
//			
//			params.put("wa", "wsignin1.0");
//			params.put("wreply", context.getSpMetadata().getDefaultAssertionConsumerService().getLocation());
//			params.put("wctx", relayState);
//			params.put("wtrealm", context.getSpMetadata().getEntityID());
//			params.put("wreq", xml);
//			vc.put("attributes", params);
//			
//			try {
//				HTTPUtils.getEngine().mergeTemplate("/dk/itst/wsfed/service/loginpost.vm", vc, context.getResponse().getWriter());
//			} catch (Exception e) {
//				e.printStackTrace();
//				throw new ServletException("Unable to render template", e);
//			}		
		}
		} catch (DatatypeConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void handlePost(RequestContext arg0) throws ServletException, IOException {
		throw new UnsupportedOperationException();
	}

}
