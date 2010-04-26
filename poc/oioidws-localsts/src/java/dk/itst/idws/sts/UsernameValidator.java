/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package dk.itst.idws.sts;

import com.sun.xml.wss.SubjectAccessor;
import com.sun.xml.wss.impl.callback.PasswordValidationCallback.PasswordValidationException;
import com.sun.xml.wss.impl.callback.PasswordValidationCallback.PasswordValidator;
import com.sun.xml.wss.impl.callback.PasswordValidationCallback.PlainTextPasswordRequest;
import com.sun.xml.wss.impl.callback.PasswordValidationCallback.Request;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapContext;
import javax.security.auth.Subject;

/**
 *
 * @author recht
 */
public class UsernameValidator implements PasswordValidator {

    public boolean validate(Request rqst) throws PasswordValidationException {
        PlainTextPasswordRequest req = (PlainTextPasswordRequest) rqst;
        String username = req.getUsername();
        String password = req.getPassword();

        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389/ou=people,dc=trifork,dc=com");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "uid=" + username + ",ou=people,dc=trifork,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            DirContext ctx = new InitialDirContext(env);

            Subject subject = SubjectAccessor.getRequesterSubject();
            if (subject == null) {
                subject = new Subject();
                SubjectAccessor.setRequesterSubject(subject);
            }
            subject.getPublicCredentials().add(new UsernamePrincipal(username));
            
            ctx.close();

            return true;
        } catch (NamingException ex) {
            Logger.getLogger(UsernameValidator.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

}
