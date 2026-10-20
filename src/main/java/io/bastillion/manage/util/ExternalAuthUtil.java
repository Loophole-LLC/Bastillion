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
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * External authentication utility for JAAS
 * <p>
 * Uses only public JAAS and Jetty API. It used to read the private fields of
 * {@link LoginContext} and {@link LdapLoginModule} by reflection, which Java 17+ refuses for
 * java.base without --add-opens, and one of the Jetty fields it named had not existed since
 * Jetty 10 - so every LDAP login failed after the directory had accepted the password.
 */
public class ExternalAuthUtil {

    private static final Logger log = LoggerFactory.getLogger(ExternalAuthUtil.class);

    public static final boolean externalAuthEnabled = StringUtils.isNotEmpty(AppConfig.getProperty("jaasModule"));
    private static final String JAAS_CONF = "jaas.conf";
    private static final String JAAS_MODULE = AppConfig.getProperty("jaasModule");
    private static final String DEFAULT_LDAP_PROFILE = AppConfig.getProperty("defaultProfileForLdap");

    //the Jetty 9-11 name of LdapLoginModule, still in jaas.conf files copied from older releases
    static final String LEGACY_LDAP_LOGIN_MODULE = "org.eclipse.jetty.jaas.spi.LdapLoginModule";


    static {
        if (externalAuthEnabled) {
            System.setProperty("java.security.auth.login.config", AppConfig.CONFIG_DIR + "/" + JAAS_CONF);
        }
    }

    private ExternalAuthUtil() {

    }

    /**
     * what a successful directory login says about the user - the name and email on user are
     * only used if the account has to be created, the roles only if a module can enumerate them
     */
    static class DirectoryLogin {
        final User user = new User();
        List<String> allRoles = null;
        List<String> assignedRoles = null;
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
                DirectoryLogin directoryLogin = authenticate(auth, Configuration.getConfiguration(), JAAS_MODULE);

                con = DBUtils.getConn();
                authToken = ExternalAccountUtil.link(con, directoryLogin.user, Auth.AUTH_EXTERNAL,
                        directoryLogin.allRoles, directoryLogin.assignedRoles, DEFAULT_LDAP_PROFILE);
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
     * Authenticates against the given JAAS module and reads what the directory knows about
     * the user. Touches no database.
     *
     * @param auth          username and password
     * @param configuration JAAS configuration holding jaasModule
     * @param jaasModule    entry name in that configuration
     * @return what the login says about the user
     * @throws LoginException if the directory rejects the credentials
     */
    static DirectoryLogin authenticate(final Auth auth, Configuration configuration, String jaasModule) throws Exception {
        configuration = withCurrentJettyNames(configuration);

        CallbackHandler callbackHandler = callbacks -> {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName(auth.getUsername());
                } else if (callback instanceof ObjectCallback) {
                    ((ObjectCallback) callback).setObject(auth.getPassword().toCharArray());
                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword(auth.getPassword().toCharArray());
                }
            }
        };

        LoginContext loginContext = new LoginContext(jaasModule, new Subject(), callbackHandler, configuration);
        //will throw exception if login fail
        loginContext.login();

        DirectoryLogin directoryLogin = new DirectoryLogin();
        directoryLogin.user.setUsername(auth.getUsername());
        if (auth.getUsername().contains("@")) {
            directoryLogin.user.setEmail(auth.getUsername());
        }

        for (AppConfigurationEntry entry : configuration.getAppConfigurationEntry(jaasModule)) {
            if (LdapLoginModule.class.getName().equals(entry.getLoginModuleName())) {
                readLdapUser(directoryLogin, auth.getUsername(), callbackHandler, entry.getOptions());
            } else {
                //if it looks like name is returned default it
                for (Principal p : loginContext.getSubject().getPrincipals()) {
                    if (p.getName().contains(" ")) {
                        String[] name = p.getName().split(" ");
                        if (name.length > 1) {
                            directoryLogin.user.setFirstNm(name[0]);
                            directoryLogin.user.setLastNm(name[name.length - 1]);
                        }
                    }
                }
            }
        }
        return directoryLogin;
    }

    /**
     * reads the user's roles, every role the directory knows about, and the user's name and
     * email, using the same connection settings and defaults as the LdapLoginModule entry
     */
    private static void readLdapUser(DirectoryLogin directoryLogin, String username, CallbackHandler callbackHandler,
                                     Map<String, ?> options) throws Exception {

        LdapLoginModule loginModule = new LdapLoginModule();
        loginModule.initialize(new Subject(), callbackHandler, new HashMap<>(), options);
        try {
            AbstractLoginModule.JAASUser userInfo = loginModule.getUser(username);
            if (userInfo != null) {
                directoryLogin.assignedRoles = userInfo.doFetchRoles();
            }

            DirContext dirContext = new InitialDirContext(loginModule.getEnvironment());
            try {
                directoryLogin.allRoles = getAllRoles(dirContext, option(options, "roleBaseDn", null),
                        option(options, "roleNameAttribute", "roleName"),
                        option(options, "roleObjectClass", "groupOfUniqueNames"));

                Attributes userAttributes = getUserAttributes(dirContext, username, option(options, "userBaseDn", null),
                        option(options, "userObjectClass", "inetOrgPerson"),
                        option(options, "userIdAttribute", "cn"));
                if (userAttributes != null) {
                    setNameAndEmail(directoryLogin.user, userAttributes);
                }
            } finally {
                dirContext.close();
            }
        } finally {
            //closes the module's own directory connection
            loginModule.abort();
        }
    }

    private static void setNameAndEmail(User user, Attributes userAttributes) throws NamingException {
        String givenName = userAttributes.get("givenName") != null ? (String) userAttributes.get("givenName").get() : null;
        String sn = userAttributes.get("sn") != null ? (String) userAttributes.get("sn").get() : null;
        String displayName = userAttributes.get("displayName") != null ? (String) userAttributes.get("displayName").get() : null;
        String cn = userAttributes.get("cn") != null ? (String) userAttributes.get("cn").get() : null;
        String email = userAttributes.get("mail") != null ? (String) userAttributes.get("mail").get() : null;

        if (StringUtils.isNotEmpty(givenName) && StringUtils.isNotEmpty(sn)) {
            user.setFirstNm(givenName);
            user.setLastNm(sn);
        } else if (StringUtils.isNotEmpty(displayName) && displayName.contains(" ")) {
            String[] name = displayName.split(" ");
            if (name.length > 1) {
                user.setFirstNm(name[0]);
                user.setLastNm(name[name.length - 1]);
            }
        } else if (StringUtils.isNotEmpty(cn) && cn.contains(" ")) {
            String[] name = cn.split(" ");
            if (name.length > 1) {
                user.setFirstNm(name[0]);
                user.setLastNm(name[name.length - 1]);
            }
        }

        if (StringUtils.isNotEmpty(email)) {
            user.setEmail(email);
        }
    }

    /**
     * the user's own entry, found the way LdapLoginModule finds it
     */
    private static Attributes getUserAttributes(DirContext dirContext, String username, String userBaseDn,
                                                String userObjectClass, String userIdAttribute) throws NamingException {
        SearchControls ctls = new SearchControls();
        ctls.setDerefLinkFlag(true);
        ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String filter = "(&(objectClass={0})({1}={2}))";
        Object[] filterArguments = {userObjectClass, userIdAttribute, username};
        NamingEnumeration<SearchResult> results = dirContext.search(userBaseDn, filter, filterArguments, ctls);
        return results.hasMoreElements() ? results.nextElement().getAttributes() : null;
    }

    private static String option(Map<String, ?> options, String name, String defaultValue) {
        Object value = options.get(name);
        return value == null ? defaultValue : value.toString();
    }

    /**
     * maps the pre-Jetty-12 LdapLoginModule class name onto the current one, so a jaas.conf
     * copied from an older release keeps loading instead of failing every login with
     * ClassNotFoundException
     */
    static Configuration withCurrentJettyNames(Configuration configuration) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                AppConfigurationEntry[] entries = configuration.getAppConfigurationEntry(name);
                if (entries == null) {
                    return null;
                }
                AppConfigurationEntry[] mapped = new AppConfigurationEntry[entries.length];
                for (int i = 0; i < entries.length; i++) {
                    AppConfigurationEntry entry = entries[i];
                    mapped[i] = LEGACY_LDAP_LOGIN_MODULE.equals(entry.getLoginModuleName())
                            ? new AppConfigurationEntry(LdapLoginModule.class.getName(), entry.getControlFlag(), entry.getOptions())
                            : entry;
                }
                return mapped;
            }
        };
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
