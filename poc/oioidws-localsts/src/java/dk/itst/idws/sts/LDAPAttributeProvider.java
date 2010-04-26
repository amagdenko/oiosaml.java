/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package dk.itst.idws.sts;

import com.sun.xml.ws.api.security.trust.Claims;
import com.sun.xml.ws.api.security.trust.STSAttributeProvider;
import com.sun.xml.wss.SubjectAccessor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.xml.namespace.QName;

/**
 *
 * @author recht
 */
public class LDAPAttributeProvider implements STSAttributeProvider {

    private Map<String, String> iodmap = new HashMap<String, String>() {{
        put("mail", "");
        put("sn", "urn:oid:2.5.4.4");
        //put("cn", "urn:oid:2.5.4.3");
        put("cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
        put("uid", "urn:oid:0.9.2342.19200300.100.1.1");
        put("mail", "urn:oid:0.9.2342.19200300.100.1.3");

    }};

    public Map<QName, List<String>> getClaimedAttributes(Subject sbjct, String string, String string1, Claims claims) {
        Map<QName, List<String>> res = new HashMap<QName, List<String>>();

        try {
            sbjct = SubjectAccessor.getRequesterSubject();
            UsernamePrincipal principal = sbjct.getPublicCredentials(UsernamePrincipal.class).iterator().next();

            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389/ou=people,dc=trifork,dc=com");

            DirContext ctx = new InitialDirContext(env);
            
            Attributes attrs = ctx.getAttributes("uid=" + principal.getName());
            NamingEnumeration<? extends Attribute> vals = attrs.getAll();
            while (vals.hasMore()) {
                Attribute val = vals.next();
                if (iodmap.containsKey(val.getID())) {
                    res.put(new QName(iodmap.get(val.getID())), Arrays.asList(val.get().toString()));
                }
            }

            res.put(new QName("ActAs"), Arrays.asList(principal.getName()));
            
            return res;
        } catch (Exception ex) {
            Logger.getLogger(LDAPAttributeProvider.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException(ex);
        }
    }

}
