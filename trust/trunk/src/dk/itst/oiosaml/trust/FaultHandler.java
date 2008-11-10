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
package dk.itst.oiosaml.trust;

import java.lang.reflect.InvocationTargetException;

import javax.xml.namespace.QName;

import org.opensaml.xml.XMLObject;

/**
 * Handle SOAP Faults.
 *
 */
public interface FaultHandler {

	/**
	 * Invoked when a SOAP fault occurs.
	 * @param faultCode The FaultCode.
	 * @param faultMessage Fault Message.
	 * @param detail The Fault detail element.
	 * @throws Exception If any exception is thrown from a handler, the exception is re-thrown as an {@link InvocationTargetException}.
	 */
	public void handleFault(QName faultCode, String faultMessage, XMLObject detail) throws Exception;
}
