/**
 * Copyright (C) 2017 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.User;
import org.apache.commons.lang3.StringUtils;

import org.eclipse.jetty.security.jaas.callback.ObjectCallback;
import org.eclipse.jetty.security.jaas.spi.AbstractLoginModule;
import org.eclipse.jetty.security.jaas.spi.LdapLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Principal;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


/**
 * External authentication utility for JAAS
 */
public class ExternalAuthUtil {

    private static final Logger log = LoggerFactory.getLogger(ExternalAuthUtil.class);

    public static final boolean externalAuthEnabled = StringUtils.isNotEmpty(AppConfig.getProperty("jaasModule"));
    private static final String JAAS_CONF = "jaas.conf";
    private static final String JAAS_MODULE = AppConfig.getProperty("jaasModule");
    private static final String DEFAULT_LDAP_PROFILE = AppConfig.getProperty("defaultProfileForLdap");


    static {
        if (externalAuthEnabled) {
            System.setProperty("java.security.auth.login.config", AppConfig.CONFIG_DIR + "/" + JAAS_CONF);
        }
    }

    private ExternalAuthUtil() {

    }


    /**
     * external auth login method
     *
     * @return auth token if success
     * @auth authentication credentials
     */
    public static String login(final Auth auth) {
        Connection con = null;
        String authToken = null;

        if (externalAuthEnabled && auth != null && StringUtils.isNotEmpty(auth.getUsername()) && StringUtils.isNotEmpty(auth.getPassword())) {

            try {
                //create login context
                LoginContext loginContext = new LoginContext(JAAS_MODULE, new CallbackHandler() {
                    @Override
                    public void handle(Callback[] callbacks) throws IOException,
                            UnsupportedCallbackException {
                        for (Callback callback : callbacks) {
                            if (callback instanceof NameCallback) {
                                ((NameCallback) callback).setName(auth
                                        .getUsername());
                            } else if (callback instanceof ObjectCallback) {
                                ((ObjectCallback) callback).setObject(auth
                                        .getPassword().toCharArray());
                            } else if (callback instanceof PasswordCallback) {
                                ((PasswordCallback) callback).setPassword(auth
                                        .getPassword().toCharArray());

                            }
                        }
                    }
                });

                //will throw exception if login fail
                loginContext.login();

                con = DBUtils.getConn();

                //what the login modules say about this user - name and email are only used if
                //the account has to be created, roles only if a module can enumerate them
                User newUser = new User();
                newUser.setUsername(auth.getUsername());
                if (auth.getUsername().contains("@")) {
                    newUser.setEmail(auth.getUsername());
                }
                List<String> allRoles = null;
                List<String> assignedRoles = null;

                Field field = LoginContext.class.getDeclaredField("moduleStack");
                field.setAccessible(true);
                Object[] modules = (Object[]) field.get(loginContext);

                for (Object entry : modules) {
                    field = entry.getClass().getDeclaredField("module");
                    field.setAccessible(true);
                    Object module = field.get(entry);

                    field = entry.getClass().getDeclaredField("entry");
                    field.setAccessible(true);
                    AppConfigurationEntry appEntry = (AppConfigurationEntry) field.get(entry);

                    if (module instanceof LdapLoginModule) {

                        //get callback handler
                        field = LoginContext.class.getDeclaredField("callbackHandler");
                        field.setAccessible(true);
                        CallbackHandler callbackHandler = (CallbackHandler) field.get(loginContext);

                        //get state
                        field = LoginContext.class.getDeclaredField("state");
                        field.setAccessible(true);
                        Map state = (Map) field.get(loginContext);

                        LdapLoginModule loginModule = (LdapLoginModule) module;
                        loginModule.initialize(loginContext.getSubject(), callbackHandler, state, appEntry.getOptions());
                        AbstractLoginModule.JAASUser userInfo = loginModule.getUser(auth.getUsername());

                        //fetch assigned roles
                        userInfo.fetchRoles();

                        //dir context context
                        field = loginModule.getClass().getDeclaredField("_rootContext");
                        field.setAccessible(true);
                        DirContext dirContext = (DirContext) field.get(loginModule);

                        //role name attribute
                        field = loginModule.getClass().getDeclaredField("_roleNameAttribute");
                        field.setAccessible(true);
                        String roleNameAttribute = (String) field.get(loginModule);

                        //base dn for role
                        field = loginModule.getClass().getDeclaredField("_roleBaseDn");
                        field.setAccessible(true);
                        String roleBaseDn = (String) field.get(loginModule);

                        //role object class
                        field = loginModule.getClass().getDeclaredField("_roleObjectClass");
                        field.setAccessible(true);
                        String roleObjectClass = (String) field.get(loginModule);

                        //all attributes for user
                        field = LdapLoginModule.LDAPBindingUser.class.getDeclaredField("attributes");
                        field.setAccessible(true);
                        Attributes userAttributes = (Attributes) field.get(userInfo);

                        allRoles = getAllRoles(dirContext, roleBaseDn, roleNameAttribute, roleObjectClass);
                        assignedRoles = userInfo.doFetchRoles();

                        // set attributes from ldap
                        String givenName = userAttributes.get("givenName") != null ? (String) userAttributes.get("givenName").get() : null;
                        String sn = userAttributes.get("sn") != null ? (String) userAttributes.get("sn").get() : null;
                        String displayName = userAttributes.get("displayName") != null ? (String) userAttributes.get("displayName").get() : null;
                        String cn = userAttributes.get("cn") != null ? (String) userAttributes.get("cn").get() : null;
                        String email = userAttributes.get("mail") != null ? (String) userAttributes.get("mail").get() : null;

                        if (StringUtils.isNotEmpty(givenName) && StringUtils.isNotEmpty(sn)) {
                            newUser.setFirstNm(givenName);
                            newUser.setLastNm(sn);
                        } else if (StringUtils.isNotEmpty(displayName) && displayName.contains(" ")) {
                            String[] name = displayName.split(" ");
                            if (name.length > 1) {
                                newUser.setFirstNm(name[0]);
                                newUser.setLastNm(name[name.length - 1]);
                            }
                        } else if (StringUtils.isNotEmpty(cn) && cn.contains(" ")) {
                            String[] name = cn.split(" ");
                            if (name.length > 1) {
                                newUser.setFirstNm(name[0]);
                                newUser.setLastNm(name[name.length - 1]);
                            }
                        }

                        if (StringUtils.isNotEmpty(email)) {
                            newUser.setEmail(email);
                        }

                        dirContext.close();
                        loginModule.commit();

                    } else {

                        Subject subject = loginContext.getSubject();

                        //if it looks like name is returned default it
                        for (Principal p : subject.getPrincipals()) {
                            if (p.getName().contains(" ")) {
                                String[] name = p.getName().split(" ");
                                if (name.length > 1) {
                                    newUser.setFirstNm(name[0]);
                                    newUser.setLastNm(name[name.length - 1]);
                                }
                            }
                        }

                    }
                }

                authToken = ExternalAccountUtil.link(con, newUser, Auth.AUTH_EXTERNAL, allRoles, assignedRoles, DEFAULT_LDAP_PROFILE);
            } catch (LoginException le) {
                authToken = null;
                log.debug(le.toString(), le);
            } catch (Exception ex) {
                authToken = null;
                log.error(ex.toString(), ex);
            } finally {
                // con is opened partway through the try block above (after LDAP/JAAS login
                // succeeds) - closing it here rather than only on the success path ensures a
                // failure partway through (e.g. a DB error while provisioning the user record)
                // doesn't leak the pooled connection.
                try {
                    DBUtils.closeConn(con);
                } catch (SQLException ex) {
                    log.error(ex.toString(), ex);
                }
            }
        }
        return authToken;
    }

    /**
     * returns all possible roles for a user
     *
     * @param dirContext        ldap directory context
     * @param roleBaseDn        base dn for roles
     * @param roleNameAttribute role name
     * @param roleObjectClass   role object class
     * @return all roles under base dn
     */
    private static List<String> getAllRoles(DirContext dirContext, String roleBaseDn, String roleNameAttribute, String roleObjectClass) throws NamingException {
        List<String> allRoles = new ArrayList<String>();
        SearchControls ctls = new SearchControls();
        ctls.setDerefLinkFlag(true);
        ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        ctls.setReturningAttributes(new String[]{roleNameAttribute});

        String filter = "(objectClass={0})";
        Object[] filterArguments = {roleObjectClass};
        NamingEnumeration<SearchResult> results = dirContext.search(roleBaseDn, filter, filterArguments, ctls);

        while (results.hasMoreElements()) {
            SearchResult result = results.nextElement();

            Attributes attributes = result.getAttributes();

            if (attributes != null) {
                Attribute roleAttribute = attributes.get(roleNameAttribute);

                if (roleAttribute != null) {

                    NamingEnumeration<?> roles = roleAttribute.getAll();
                    while (roles.hasMore()) {
                        allRoles.add(roles.next().toString());
                    }
                }
            }
        }
        return allRoles;
    }
}