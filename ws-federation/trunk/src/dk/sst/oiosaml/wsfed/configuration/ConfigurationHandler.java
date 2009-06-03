package dk.sst.oiosaml.wsfed.configuration;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.apache.velocity.VelocityContext;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.security.CredentialRepository;
import dk.itst.oiosaml.sp.service.RequestContext;
import dk.itst.oiosaml.sp.service.util.Constants;

public class ConfigurationHandler extends dk.itst.oiosaml.sp.configuration.ConfigurationHandler {

	public static final String SESSION_CONFIGURATION = "CONFIGURATION";
	private static final Logger log = Logger.getLogger(ConfigurationHandler.class);
	private final ServletContext servletContext;
	
	public ConfigurationHandler(ServletContext sc) {
		super(sc);
		this.servletContext = sc;
	}

	public void handlePost(RequestContext context) throws ServletException, IOException {
		HttpServletRequest request = context.getRequest();
		HttpServletResponse response = context.getResponse();
		
		if (!checkConfiguration(response)) return;
		
		List<?> parameters = extractParameterList(request);
		
		String stsLocation = extractParameter("stsLocation", parameters);
		String stsEntityId = extractParameter("stsEntityId", parameters);
		String entityId = extractParameter("entityId", parameters);
		final String password = extractParameter("keystorePassword", parameters);
		byte[] stsKeystore = extractFile("stsKeystore", parameters).get();
		FileItem ksData = extractFile("keystore", parameters);
		byte[] keystore = null;
		if (ksData != null) {
			keystore = ksData.get();
		}
		log.debug("STS Keystore: " + stsKeystore);
		if (!checkNotNull(stsLocation, password, stsKeystore, entityId, stsEntityId)
				|| stsKeystore.length == 0
				|| (keystore == null && !Boolean.valueOf(extractParameter("createkeystore", parameters)))) {
			Map<String, Object> params = getStandardParameters(request);
			params.put("error", "All fields must be filled.");
			params.put("stsLocation", stsLocation);
			params.put("keystorePassword", password);
			params.put("entityId", entityId);
			params.put("stsEntityId", stsEntityId);
			log.info("Parameters not correct: " + params);
			
			String res = renderTemplate("configure.vm", params, true);
			sendResponse(response, res);
			return;
		}
		
		Credential credential = context.getCredential();
		if (keystore != null && keystore.length > 0) {
			credential  = CredentialRepository.createCredential(new ByteArrayInputStream(keystore), password);
		} else if (Boolean.valueOf(extractParameter("createkeystore", parameters))) {
			try {
				BasicX509Credential cred = new BasicX509Credential();
				KeyPair kp = dk.itst.oiosaml.security.SecurityHelper.generateKeyPairFromURI("http://www.w3.org/2001/04/xmlenc#rsa-1_5", 1024);
				cred.setPrivateKey(kp.getPrivate());
				cred.setPublicKey(kp.getPublic());
				credential = cred;
				
				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(null, null);
				X509Certificate cert = dk.itst.oiosaml.security.SecurityHelper.generateCertificate(credential, getEntityId(request));
				cred.setEntityCertificate(cert);
				
				ks.setKeyEntry("oiosaml", credential.getPrivateKey(), password.toCharArray(), new Certificate[] { 
					cert });
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ks.store(bos, password.toCharArray());
				
				keystore = bos.toByteArray();
				bos.close();
			} catch (Exception e) {
				log.error("Unable to generate credential", e);
				throw new RuntimeException("Unable to generate credential", e);
			}
		}
		
		EntityDescriptor descriptor = generateSPDescriptor(getBaseUrl(request), entityId, credential, parameters);
		EntityDescriptor idpDescriptor = generateIdPDescriptor(stsEntityId, stsLocation, stsKeystore);
		File zipFile = generateZipFile(request.getContextPath(), password, keystore, idpDescriptor, descriptor);
		
		byte[] configurationContents = saveConfigurationInSession(request, zipFile);
		boolean written = writeConfiguration(getHome(servletContext), configurationContents);
		
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("home", getHome(servletContext));
		params.put("written", written);
		sendResponse(response, renderTemplate("done.vm", params, true));
	}


	private EntityDescriptor generateIdPDescriptor(String stsEntityId, String stsLocation, byte[] stsKeystore) {
		EntityDescriptor descriptor = SAMLUtil.buildXMLObject(EntityDescriptor.class);
		descriptor.setEntityID(stsEntityId);

		IDPSSODescriptor desc = SAMLUtil.buildXMLObject(IDPSSODescriptor.class);
		desc.addSupportedProtocol("http://schemas.xmlsoap.org/ws/2006/12/federation");
		
		KeyDescriptor signingDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		signingDescriptor.setUse(UsageType.SIGNING);
		KeyDescriptor encryptionDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		encryptionDescriptor.setUse(UsageType.ENCRYPTION);

		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(stsKeystore));
			BasicX509Credential credential = new BasicX509Credential();
			credential.setEntityCertificate(cert);
			
			KeyInfoGenerator gen = SecurityHelper.getKeyInfoGenerator(credential, org.opensaml.xml.Configuration.getGlobalSecurityConfiguration(), null);
			signingDescriptor.setKeyInfo(gen.generate(credential));
			encryptionDescriptor.setKeyInfo(gen.generate(credential));
		} catch (SecurityException e1) {
			throw new WrappedException(Layer.BUSINESS, e1);
		} catch (CertificateException e) {
			throw new WrappedException(Layer.BUSINESS, e);
		}
		desc.getKeyDescriptors().add(signingDescriptor);
		desc.getKeyDescriptors().add(encryptionDescriptor);
		
		SingleSignOnService sso = SAMLUtil.buildXMLObject(SingleSignOnService.class);
		sso.setBinding("http://schemas.xmlsoap.org/ws/2006/12/federation");
		sso.setLocation(stsLocation);
		desc.getSingleSignOnServices().add(sso);

		//TODO: Check that the location should be the same
		SingleLogoutService slo = SAMLUtil.buildXMLObject(SingleLogoutService.class);
		slo.setBinding("http://schemas.xmlsoap.org/ws/2006/12/federation");
		slo.setLocation(stsLocation);
		desc.getSingleLogoutServices().add(slo);
		
		descriptor.getRoleDescriptors().add(desc);
		return descriptor;
	}

	private byte[] saveConfigurationInSession(final HttpServletRequest request, File zipFile) throws IOException, FileNotFoundException {
		byte[] configurationContents = IOUtils.toByteArray(new FileInputStream(zipFile));
		request.getSession().setAttribute(SESSION_CONFIGURATION, configurationContents);
		return configurationContents;
	}

	protected File generateZipFile(final String contextPath, final String password, byte[] keystore, EntityDescriptor idpMetadata, EntityDescriptor descriptor) throws IOException {
		File zipFile = File.createTempFile("oiosaml-", ".zip");
		ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile));
		zos.putNextEntry(new ZipEntry("oiosaml-sp.properties"));
		zos.write(renderTemplate("defaultproperties.vm", new HashMap<String, Object>() {{
			put("homename", Constants.PROP_HOME);

			put("servletPath", contextPath);
			put("password", password);
		}}, false).getBytes());
		zos.closeEntry();
		
		zos.putNextEntry(new ZipEntry("metadata/SP/SPMetadata.xml"));
		zos.write(SAMLUtil.getSAMLObjectAsPrettyPrintXML(descriptor).getBytes());
		zos.closeEntry();
		
		zos.putNextEntry(new ZipEntry("metadata/IdP/IdPMetadata.xml"));
		zos.write(SAMLUtil.getSAMLObjectAsPrettyPrintXML(idpMetadata).getBytes());
		zos.closeEntry();
		
		zos.putNextEntry(new ZipEntry("certificate/keystore"));
		zos.write(keystore);
		zos.closeEntry();
		
		zos.putNextEntry(new ZipEntry("oiosaml-sp.log4j.xml"));
		IOUtils.copy(getClass().getResourceAsStream("oiosaml-sp.log4j.xml"), zos);
		zos.closeEntry();
		
		zos.close();
		return zipFile;
	}

	protected EntityDescriptor generateSPDescriptor(String baseUrl, String entityId, Credential credential, List<?> parameters) {
		EntityDescriptor descriptor = SAMLUtil.buildXMLObject(EntityDescriptor.class);
		descriptor.setEntityID(entityId);
		
		SPSSODescriptor spDescriptor = SAMLUtil.buildXMLObject(SPSSODescriptor.class);
		spDescriptor.setAuthnRequestsSigned(true);
		spDescriptor.setWantAssertionsSigned(true);
		
		KeyDescriptor signingDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		signingDescriptor.setUse(UsageType.SIGNING);
		KeyDescriptor encryptionDescriptor = SAMLUtil.buildXMLObject(KeyDescriptor.class);
		encryptionDescriptor.setUse(UsageType.ENCRYPTION);

		try {
			KeyInfoGenerator gen = SecurityHelper.getKeyInfoGenerator(credential, org.opensaml.xml.Configuration.getGlobalSecurityConfiguration(), null);
			signingDescriptor.setKeyInfo(gen.generate(credential));
			encryptionDescriptor.setKeyInfo(gen.generate(credential));
		} catch (SecurityException e1) {
			throw new WrappedException(Layer.BUSINESS, e1);
		}
		spDescriptor.getKeyDescriptors().add(signingDescriptor);
		spDescriptor.getKeyDescriptors().add(encryptionDescriptor);
		
		spDescriptor.addSupportedProtocol("http://schemas.xmlsoap.org/ws/2006/12/federation");
		spDescriptor.getAssertionConsumerServices().add(SAMLUtil.createAssertionConsumerService(baseUrl + "/WSFedConsumer", "http://schemas.xmlsoap.org/ws/2006/12/federation", 0, true));
		
		spDescriptor.getSingleLogoutServices().add(SAMLUtil.createSingleLogoutService(baseUrl + "/WSFedConsumer", baseUrl + "/WSFedConsumer", "http://schemas.xmlsoap.org/ws/2006/12/federation"));
		
		
		descriptor.getRoleDescriptors().add(spDescriptor);
		return descriptor;
	}


	private List<?> extractParameterList(final HttpServletRequest request) {
		List<?> parameters;
		try {
			FileItemFactory itemFactory = new DiskFileItemFactory();
			parameters = new ServletFileUpload(itemFactory).parseRequest(request);
		} catch (FileUploadException e) {
			log.error("Unable to parse uploaded files", e);
			throw new RuntimeException("Unable to parse uploaded files", e);
		}
		return parameters;
	}

	private boolean checkConfiguration(HttpServletResponse response)
			throws IOException {
		if (isConfigured(servletContext)) {
			sendResponse(response, renderTemplate("alreadyConfigured.vm", new HashMap<String, Object>() {{
				put("home", getHome(servletContext));
			}}, true));
			return false;
		}
		return true;
	}
	
	private FileItem extractFile(String name, List<?> files) {
		for (Iterator<?> i = files.iterator(); i.hasNext();) {
			FileItem file = (FileItem) i.next();
			if (!file.isFormField() && file.getFieldName().equals(name)) {
				return file;
			}
		}
		return null;
	}
	
	private String extractParameter(String name, List<?> files) {
		for (Iterator<?> i = files.iterator(); i.hasNext();) {
			FileItem file = (FileItem) i.next();
			if (file.isFormField() && file.getFieldName().equals(name)) {
				return "".equals(file.getString()) ? null : file.getString();
			}
		}
		return null;
	}
	
	private void sendResponse(HttpServletResponse response, String res) throws IOException {
		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(res);
	}
	
	protected String getBaseUrl(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		int idx = url.lastIndexOf(request.getServletPath());
		
		return url.substring(0, idx + request.getServletPath().length());
	}
	
	protected boolean isHomeAvailable(ServletContext ctx) {
		String home = getHome(ctx);
		if (home == null) return false;
		
		if (new File(home).isDirectory()) {
			return true;
		} else {
			return false;
		}
	}
	
	protected boolean isConfigured(ServletContext ctx) {
		String home = getHome(ctx);
		if (home == null) return false;
		
		File homeDir = new File(home);
		String[] files = homeDir.list();
		if (files == null || files.length > 0) {
			return true;
		} else {
			return false;
		}
	}
	
	protected String renderTemplate(String template, Map<String, Object> objects, boolean html) {
		VelocityContext ctx = new VelocityContext();
		for (Map.Entry<String, Object> e : objects.entrySet()) {
			ctx.put(e.getKey(), e.getValue());
		}
		
		StringWriter w = new StringWriter();
		
		try {
			String prefix = "/" + getClass().getPackage().getName().replace('.', '/') + "/";
			if (html) {
				engine.mergeTemplate(prefix + "head.vm", ctx, w);
			}
			engine.mergeTemplate(prefix + template, ctx, w);
			if (html) {
				engine.mergeTemplate(prefix + "foot.vm", ctx, w);
			}
		} catch (Exception e) {
			log.error("Unable to merge templates", e);
		}
		return w.toString();
	}

	private String getHome(ServletContext ctx) {
		String home = ctx.getInitParameter(Constants.INIT_OIOSAML_HOME);
		if (home == null) {
			home = System.getProperty(SAMLUtil.OIOSAML_HOME);
		}
		if (home == null) {
			String name = ctx.getInitParameter(Constants.INIT_OIOSAML_NAME);
			if (name != null) {
				home = System.getProperty("user.home") + "/.oiosaml-" + name;
			}
		}
		if (home == null) {
			home = System.getProperty("user.home") + "/.oiosaml";
			File h = new File(home);
			if (h.exists() && !h.isDirectory()) {
				throw new IllegalStateException(home + " is not a directory");
			} else if (!h.exists()) {
				log.info("Creating empty config dir in " + home);
				if (!h.mkdir()) {
					throw new IllegalStateException(h + " could not be created");
				}
			}
		}
		return home;
	}
	
	private String getEntityId(HttpServletRequest request) {
		return request.getScheme() + "://saml." + request.getServerName();
	}
	
	private boolean checkNotNull(Object ... objs) {
		for (Object o : objs) {
			if (o == null) {
				return false;
			}
		}
		return true;
	}
	
	protected Map<String, Object> getStandardParameters(HttpServletRequest request) {
		String base = getBaseUrl(request);
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("wsfedUrl", base + "/WSFedConsumer");
		params.put("logoutUrl", base + "/WSFedLogout");
		params.put("logoutRequestUrl", base + "/WSFedConsumer");
		params.put("home", getHome(servletContext));
		params.put("entityId", getEntityId(request));
		return params;
	}

}
