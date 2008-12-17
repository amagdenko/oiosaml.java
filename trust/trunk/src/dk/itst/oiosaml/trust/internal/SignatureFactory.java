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

import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;

import dk.itst.oiosaml.trust.internal.apache.dom.XMLDSigRI;

public class SignatureFactory {
	private static final Logger log = Logger.getLogger(SignatureFactory.class);
	
	private static XMLSignatureFactory instance;

	@SuppressWarnings("unchecked")
	public static XMLSignatureFactory getInstance() {
		if (instance == null) {
			registerTransform();
			
			Provider p = new XMLDSigRI() {
				{
					final Map map = new HashMap();

//					map.put("XMLSignatureFactory.DOM", DOMXMLSignatureFactory.class.getName());

					map.put("TransformService." + STRTransform.implementedTransformURI, DOMSTRTransform.class.getName());
					map.put("Alg.Alias.TransformService.STRTRANSFORM", STRTransform.implementedTransformURI);
					map.put("TransformService." + STRTransform.implementedTransformURI + " MechanismType", "DOM");

					putAll(map);
				}
			};
			try {
				instance = XMLSignatureFactory.getInstance("DOM", p);
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		return instance;
	}

    private static void registerTransform() {
		try {
			org.apache.xml.security.transforms.Transform.register(STRTransform.implementedTransformURI, STRTransform.class.getName());
			log.debug("STR-Transform registered");
		} catch (AlgorithmAlreadyRegisteredException e) {
			log.info("STR-Transform already registered", e);
		}
//		try {
//			Class<?> ct = Class.forName("com.sun.org.apache.xml.internal.security.transforms.Transform");
//			try {
//				Method init = ct.getDeclaredMethod("init");
//				init.invoke(null);
//				
//				Method m = ct.getDeclaredMethod("register", String.class, String.class);
//				m.invoke(null, STRTransform.implementedTransformURI, SunSTRTransform.class.getName());
//			} catch (Exception e) {
//				log.fatal("Unable to register transform", e);
//			}
//		} catch (ClassNotFoundException e) {
//			log.info("Not running on recent sun java vm, ignoring internal transform");
//		}
	}
	

}
