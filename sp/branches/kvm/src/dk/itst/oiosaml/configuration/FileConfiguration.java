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
 *   Aage Nielsen <ani@openminds.dk>
 *   Carsten Larsen <cas@schultz.dk>
 *
 */
package dk.itst.oiosaml.configuration;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.XMLObject;

import dk.itst.oiosaml.common.SAMLUtil;
import dk.itst.oiosaml.error.Layer;
import dk.itst.oiosaml.error.WrappedException;
import dk.itst.oiosaml.sp.service.SPFilter;
import dk.itst.oiosaml.sp.service.util.Constants;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * Utility class to obtain a handle to all property values within the current
 * project.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 * @author Aage Nielsen <ani@openminds.dk>
 * @author Carsten Larsen <cas@schultz.dk>
 * 
 */
public class FileConfiguration implements SAMLConfiguration {
	private static final Logger log = Logger.getLogger(FileConfiguration.class);
	private String homeDir;
	private String configurationFileName;
	private Configuration systemConfiguration;

    public FileConfiguration() {
        setInitSPFilter();
    }

    /**
	 * Get the current system configuration. The configuration is stored in
	 * {@link SAMLUtil#OIOSAML_HOME}. The property is normally set in
	 * {@link SPFilter}.
	 * 
	 * @throws IllegalStateException
	 *             When the system has not been configured properly yet.
	 */
	public Configuration getSystemConfiguration() throws IllegalStateException {
		if (systemConfiguration != null)
			return systemConfiguration;
		if (homeDir == null || !isConfigured()) {
			throw new IllegalStateException("System not configured");
		}

		CompositeConfiguration conf = new CompositeConfiguration();
		conf.setProperty("oiosaml.home", homeDir);

		try {
			conf.addConfiguration(new PropertiesConfiguration(new File(homeDir, configurationFileName)));
			conf.addConfiguration(getCommonConfiguration());

			systemConfiguration = conf;
			return systemConfiguration;
		} catch (ConfigurationException e) {
			log.error("Cannot load the configuration file", e);
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (IOException e) {
			log.error("Unable to load oiosaml-common.propeties from classpath", e);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
	}

	public Configuration getCommonConfiguration() throws IOException {
		CompositeConfiguration conf = new CompositeConfiguration();
		Enumeration<URL> resources = SAMLConfiguration.class.getClassLoader().getResources("oiosaml-common.properties");
		while (resources.hasMoreElements()) {
			URL u = resources.nextElement();
			log.debug("Loading config from " + u);
			try {
				conf.addConfiguration(new PropertiesConfiguration(u));
			} catch (ConfigurationException e) {
				log.error("Cannot load the configuration file", e);
				throw new WrappedException(Layer.DATAACCESS, e);
			}
		}

		return conf;
	}

	public boolean isConfigured() {
		if (homeDir == null)
			return false;

		log.info("Config filename: " + homeDir + configurationFileName);
		File config = new File(homeDir + configurationFileName);

		log.info("Looking in : " + config.getAbsolutePath());
		return config.exists();
	}

	public KeyStore getKeystore() throws WrappedException {
		KeyStore keystore = null;

		String keystoreFileName = (homeDir == null) ? getSystemConfiguration().getString(
				Constants.PROP_CERTIFICATE_LOCATION) : homeDir
				+ getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_LOCATION);
		try {
			InputStream input = new FileInputStream(keystoreFileName);
			input = new BufferedInputStream(input);
			input.mark(1024 * 1024);
			try {
				keystore = loadStore(input, getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD),
						"PKCS12");
			} catch (IOException e) {
				log.debug("Keystore is not of type 'PCKS12' Trying type 'JKS'.");
				try {
					input.reset();
					keystore = loadStore(input,
							getSystemConfiguration().getString(Constants.PROP_CERTIFICATE_PASSWORD), "JKS");
				} catch (IOException ioe) {
					log.error("Unable to find keystore file. Looking for: " + keystoreFileName);
					throw new WrappedException(Layer.DATAACCESS, ioe);
				} catch (Exception ec) {
					log.error("Exception occured while processing keystore: " + keystoreFileName);
					throw new WrappedException(Layer.DATAACCESS, ec);
				}
			} catch (Exception ex) {
				log.error("Exception occured while processing keystore: " + keystoreFileName);
				throw new WrappedException(Layer.DATAACCESS, ex);
			}

		} catch (FileNotFoundException e) {
			log.error("Unable to find keystore file. Looking for: " + keystoreFileName);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
		return keystore;
	}

	private KeyStore loadStore(InputStream input, String password, String type) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(type);
		char[] jksPassword = password.toCharArray();
		ks.load(input, jksPassword);
		input.close();
		return ks;
	}

	public InputStream getLoggerConfiguration() throws WrappedException {
		String logFileName = homeDir + getSystemConfiguration().getString(Constants.PROP_LOG_FILE_NAME);

		String modified = null;
		StringBuilder contents = new StringBuilder();

		try {
			BufferedReader input = new BufferedReader(new FileReader(logFileName));

			int val;
			while ((val = input.read()) != -1) {
				contents.append((char) val);
			}

			modified = contents.toString().replaceAll("\\$\\{oiosaml.home\\}", homeDir.replaceAll("\\\\", "\\\\\\\\"));

		} catch (FileNotFoundException e) {
			log.error("Unable to find log file. Tries to look for: " + logFileName);
			throw new WrappedException(Layer.DATAACCESS, e);
		} catch (IOException e) {
			log.error("Unable to process log file.");
			throw new WrappedException(Layer.DATAACCESS, e);
		}

		return new ByteArrayInputStream(modified.getBytes());
	}

	public XMLObject getSPMetaData() throws WrappedException {
		String filename = getSystemConfiguration().getString(Constants.SP_METADATA_FILE);
		String directory = homeDir + getSystemConfiguration().getString(Constants.SP_METADATA_DIRECTORY);
		String spMetadataFileName = directory + "/" + filename;

		XMLObject unmarshallElementFromFile = null;
		try {
			unmarshallElementFromFile = SAMLUtil.unmarshallElementFromFile(spMetadataFileName);
		} catch (Exception e) {
			log.error("Unable to find SP metadata file. Tries to look for: " + spMetadataFileName);
			throw new WrappedException(Layer.DATAACCESS, e);
		}
		return unmarshallElementFromFile;
	}

	public List<XMLObject> getListOfIdpMetadata() throws WrappedException {
		List<XMLObject> descriptors = new ArrayList<XMLObject>();
		String protocol = getSystemConfiguration().getString(Constants.PROP_PROTOCOL);
		if (getSystemConfiguration().getString(Constants.IDP_METADATA_FILE) != null) {
			String idpFileName = homeDir + getSystemConfiguration().getString(Constants.IDP_METADATA_DIRECTORY) + "/"
					+ getSystemConfiguration().getString(Constants.IDP_METADATA_FILE);
			File md = new File(idpFileName);
			log.info("Loading " + protocol + " metadata from " + md);
			try {
				XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(md.getAbsolutePath());
				if (descriptor instanceof EntityDescriptor) {
					descriptors.add(descriptor);
				} else if (descriptor instanceof EntitiesDescriptor) {
					EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
					descriptors.addAll(desc.getEntityDescriptors());
				} else {
					throw new RuntimeException("Metadata file " + md + " does not contain an EntityDescriptor. Found "
							+ descriptor.getElementQName() + ", expected " + EntityDescriptor.ELEMENT_QNAME);
				}
			} catch (RuntimeException e) {
				log.error("Unable to load metadata from " + md
						+ ". File must contain valid XML and have EntityDescriptor as top tag", e);
				throw e;
			}
		} else {
			String directory = homeDir + getSystemConfiguration().getString(Constants.IDP_METADATA_DIRECTORY);
			File idpDir = new File(directory);
			File[] files = idpDir.listFiles(new FilenameFilter() {
				public boolean accept(File dir, String name) {
					return name.toLowerCase().endsWith(".xml");
				}
			});
			if (files != null) {
				for (File md : files) {
					log.info("Loading " + protocol + " metadata from " + md);
					try {
						XMLObject descriptor = SAMLUtil.unmarshallElementFromFile(md.getAbsolutePath());
						if (descriptor instanceof EntityDescriptor) {
							descriptors.add(descriptor);
						} else if (descriptor instanceof EntitiesDescriptor) {
							EntitiesDescriptor desc = (EntitiesDescriptor) descriptor;
							descriptors.addAll(desc.getEntityDescriptors());
						} else {
							throw new RuntimeException("Metadata file " + md
									+ " does not contain an EntityDescriptor. Found " + descriptor.getElementQName()
									+ ", expected " + EntityDescriptor.ELEMENT_QNAME);
						}
					} catch (RuntimeException e) {
						log.error("Unable to load metadata from " + md
								+ ". File must contain valid XML and have EntityDescriptor as top tag", e);
						throw e;
					}
				}
			}
		}
		if (descriptors.isEmpty()) {
			throw new IllegalStateException("No IdP descriptors found in ! At least one file is required.");
		}
		return descriptors;
	}

    private void setInitSPFilter(){
        String fullPathToConfigurationFile = null;
        String homeParam = null;
        String applicationName = null;

        // Get the base naming context
        try {
            Context env = (Context)new InitialContext().lookup("java:comp/env");

            // Read in application name
            try {
                applicationName = (String)env.lookup(Constants.INIT_OIOSAML_NAME);
            } catch (NamingException e) {
                log.info(Constants.INIT_OIOSAML_NAME + " was not defined in web.xml.");
            }

            // Read in path to configuration library
            try {
                homeParam = (String)env.lookup(Constants.INIT_OIOSAML_HOME);
            } catch (NamingException e) {
                log.info(Constants.INIT_OIOSAML_HOME + " was not defined in web.xml.");
            }

            // Read in name of configuration file
            try {
                fullPathToConfigurationFile = (String)env.lookup(Constants.INIT_OIOSAML_FILE);
            } catch (NamingException e) {
                log.info(Constants.INIT_OIOSAML_FILE + " was not defined in web.xml.");
            }
        } catch (NamingException e) {
            log.error("Unable to create InitialContext in FileConfiguration");
        }

        /*if (homeDir == null) {
            homeDir = System.getProperty(SAMLUtil.OIOSAML_HOME);
            if (homeDir == null || homeDir.trim().isEmpty()) {
                log.info(Constants.INIT_OIOSAML_HOME + " was not defined in a java system property called " + SAMLUtil.OIOSAML_HOME);
                log.info(Constants.INIT_OIOSAML_HOME + " was not defined. Default value '${user.home}/.oiosaml' is used.");
                homeDir = System.getProperty("user.home") + "/.oiosaml";
            }
        }

        if (fullPathToConfigurationFile == null) {
            log.info(Constants.INIT_OIOSAML_FILE + " was not defined. Default value " + SAMLUtil.OIOSAML_PROPERTIES_DEFAULT_FILE_NAME + " is used.");
            fullPathToConfigurationFile = SAMLUtil.OIOSAML_PROPERTIES_DEFAULT_FILE_NAME;
        }  */

        // Handle multiple application configurations
        //if(applicationName != null){
        //    homeDir += "-" + applicationName;
        //}

        // Apply '/' if not present in the end of homeDir
        //if(!homeDir.endsWith("/")){
        //    homeDir += "/";
        //}

        Map<String, String> params = new HashMap<String, String>();
        if (fullPathToConfigurationFile != null) {
            log.info(Constants.INIT_OIOSAML_FILE + " set to " + fullPathToConfigurationFile + " in web.xml");
            params.put(Constants.INIT_OIOSAML_FILE, fullPathToConfigurationFile);
        } else {
            log.info(Constants.INIT_OIOSAML_HOME + " set to " + homeParam + " in web.xml");
            log.info(Constants.INIT_OIOSAML_NAME + " set to " + applicationName + " in web.xml");

            // Locate path to configuration folder if not set in web.xml
            if (homeParam == null) {
                homeParam = System.getProperty(SAMLUtil.OIOSAML_HOME);
                log.info(Constants.INIT_OIOSAML_HOME + " not set in web.xml. Setting it to " + SAMLUtil.OIOSAML_HOME + " Java system property with value: " + homeParam);
            }
            if (homeParam == null) {
                homeParam = System.getProperty("user.home") + "/.oiosaml";
                log.info(Constants.INIT_OIOSAML_HOME + " not set in Java system property. Setting it to default path: " + homeParam);
            }

            // Apply application name if configured
            if(applicationName != null && !applicationName.trim().isEmpty()){
                homeParam += "-" + applicationName;
            }

            // Add '/' in the end if not present
            if ((homeParam != null) && (!homeParam.endsWith("/")))
                homeParam = homeParam + "/";

            log.info("Using default configuration file name: " + SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE);
            params.put(Constants.INIT_OIOSAML_FILE, homeParam + SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE);
        }

        setInitConfiguration(params);

        // Write configurations to the log
        log.info("Path to configuration folder set to: " + homeDir);
        log.info("Configuration file name set to: " + configurationFileName);
    }

	public void setInitConfiguration(Map<String, String> params) {
		systemConfiguration = null;
		if (params != null) {
			if (params.containsKey(Constants.INIT_OIOSAML_FILE)) {
				setupHomeAndFile(params.get(Constants.INIT_OIOSAML_FILE));
			} else {
				String p = params.get(Constants.INIT_OIOSAML_HOME);
				if ((p != null) && (!p.endsWith("/")))
					p = p + "/";
				homeDir = p;
				configurationFileName = params.get(Constants.INIT_OIOSAML_NAME);
			}
		}
	}

	private void setupHomeAndFile(String configurationFile) {
		if (configurationFile != null) {
			int lastPathSeperatorIndex = configurationFile.lastIndexOf("/") + 1;
			configurationFileName = configurationFile.substring((lastPathSeperatorIndex), configurationFile.length());
			homeDir = configurationFile.substring(0, lastPathSeperatorIndex);
		}
	}

	public void setConfiguration(Configuration configuration) {
		systemConfiguration = configuration;
	}

//    /**
//     * Returns the folder containing the ear file
//     *
//     * @return ear-folder
//     */
//    private String getAlternativeLocation() {
//        // Home is not be set or wrong try to locate it
//        String filePath = this.getClass().getProtectionDomain().getCodeSource().getLocation().getFile();
//        log.info("Found classpath: " + filePath);
//        int indexOfEar = filePath.indexOf(".ear");
//        String onlyPath = ".";
//        if (indexOfEar > 0) {
//            onlyPath = filePath.substring(0, indexOfEar);
//            int indexOfLastSlash = onlyPath.lastIndexOf("/") + 1;
//            int protocolIndex = onlyPath.lastIndexOf(':') + 1;
//            onlyPath = onlyPath.substring(protocolIndex, indexOfLastSlash); // remove
//            // file:
//            // from
//            // string
//            log.info("Using only path part: " + onlyPath);
//        }
//        return onlyPath;
//    }
//
//    /**
//     * Tries to locate the configuration in the ear file
//     *
//     * @param configurationFileName
//     * @return configurationFileName
//     */
//    private String getAlternativeConfigurationFileName(String configurationFileName) {
//        String onlyPath = getAlternativeLocation();
//        String onlyFileName = null;
//        if (configurationFileName != null) {
//            onlyFileName = configurationFileName.substring((configurationFileName.lastIndexOf("/") + 1), configurationFileName.length());
//        }
//        log.info("And only filename part from context: " + onlyFileName);
//        if (onlyFileName == null) {
//            onlyFileName = SAMLUtil.OIOSAML_DEFAULT_CONFIGURATION_FILE;
//        }
//        configurationFileName = onlyPath + onlyFileName;
//        return configurationFileName;
//    }
}