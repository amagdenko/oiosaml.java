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
package dk.itst.oiosaml.sp.metadata;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SingleSignOnService;

import dk.itst.oiosaml.configuration.BRSConfiguration;
import dk.itst.oiosaml.sp.util.BRSUtil;

/**
 * Utility class to extract relevant values of the meta data related to the service provider.
 * 
 * @author Joakim Recht <jre@trifork.com>
 * @author Rolf Njor Jensen <rolf@trifork.com>
 *
 */
public class SPMetadata {
	public static final String VERSION = "$Id: SPMetadata.java 2950 2008-05-28 08:22:34Z jre $";
	public static final String METADATA_FILE = "common.saml2.metadata.sp.filename";
	public static final String METADATA_DIRECTORY = "common.saml2.metadata.sp.directory";
	
	private static final Logger log = Logger.getLogger(SPMetadata.class);
	
    private EntityDescriptor entityDescriptor;
    private SPSSODescriptor spSSODescriptor;
	private static SPMetadata instance;
    
	public SPMetadata(EntityDescriptor entityDescriptor) {
		this.entityDescriptor = entityDescriptor;
		spSSODescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
	}

    public static SPMetadata getInstance() {
    	if (instance == null) {
	    	Configuration conf = BRSConfiguration.getSystemConfiguration();
	        String directory = BRSConfiguration.getStringPrefixedWithBRSHome(conf, METADATA_DIRECTORY);
	        String fileName = conf.getString(METADATA_FILE);
	        try {
		        instance = new SPMetadata( (EntityDescriptor) BRSUtil.unmarshallElementFromFile(directory+"/"+fileName));
	        } catch (Exception e) {
	        	log.error("Cannot load the metadata file: "+fileName+" - "+e.getMessage(), e);
	        	throw new IllegalArgumentException(e.getMessage());
	        }
    	} 
    	return instance;
    }
    
    public static void setMetadata(SPMetadata metadata) {
		instance = metadata;
    }
    
    
    /**
     * 
     * @return The entityID of the service provider
     */
    public String getEntityID() {
    	return entityDescriptor.getEntityID();
    }
    
    /**
     * Get the default assertion consumer service. If there is no default, the first is selected. 
     */
    public AssertionConsumerService getDefaultAssertionConsumerService() {
    	AssertionConsumerService service = spSSODescriptor.getDefaultAssertionConsumerService();
    	if (service != null) return service;
    	if (spSSODescriptor.getAssertionConsumerServices().isEmpty()) throw new IllegalStateException("No AssertionConsumerServices defined in SP metadata");
    	return spSSODescriptor.getAssertionConsumerServices().get(0);
    }
    
    /**
	 * 
	 * @param index
	 * @return The location (URL) of {@link AssertionConsumerService} no.
	 *         <code>index</code> at the service provider
	 */
    public String getAssertionConsumerServiceLocation(int index) {
    	if (spSSODescriptor.getAssertionConsumerServices().size() > index) {
    		AssertionConsumerService consumerService = spSSODescriptor.getAssertionConsumerServices().get(index);
    		return consumerService.getLocation();
    	}
    	return null;
    }

    /**
	 * 
	 * @return The location (URL) of {@link SingleSignOnService} at the service provider for HTTP-Redirect
	 */
    public  String getSingleLogoutServiceHTTPRedirectLocation() {
    	for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
    		if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
        		return singleLogoutService.getLocation();
    		}
    	}
    	return null;
    }

    /**
	 * 
	 * @return The response location (URL) of {@link SingleSignOnService} at the
	 *         service provider for HTTP-Redirect
	 */
    public  String getSingleLogoutServiceHTTPRedirectResponseLocation() {
    	for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
    		if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(singleLogoutService.getBinding())) {
        		return singleLogoutService.getResponseLocation();
    		}
    	}
    	return null;
    }
    
    /**
	 * 
	 * @return The location (URL) of {@link SingleSignOnService} at the service provider for SOAP
	 */
    public  String getSingleLogoutServiceSOAPLocation() {
    	for (SingleLogoutService singleLogoutService : spSSODescriptor.getSingleLogoutServices()) {
    		if (SAMLConstants.SAML2_SOAP11_BINDING_URI.equals(singleLogoutService.getBinding())) {
        		return singleLogoutService.getLocation();
    		}
    	}
    	return null;
    }

}
