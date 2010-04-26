/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package dk.itst.idws.sts;

import java.security.Principal;

/**
 *
 * @author recht
 */
public class UsernamePrincipal implements Principal {
    private String name;

    public UsernamePrincipal(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
