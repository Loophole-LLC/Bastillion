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

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ServiceUnavailableException;
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
import java.security.GeneralSecurityException;
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
     * @return auth token if success, null if the directory rejected the credentials or
     * external auth is off
     * @throws ExternalAuthException if the directory could not be asked
     * @auth authentication credentials
     */
    public static String login(final Auth auth) throws ExternalAuthException, SQLException, GeneralSecurityException {

        if (!externalAuthEnabled || auth == null || StringUtils.isEmpty(auth.getUsername()) || StringUtils.isEmpty(auth.getPassword())) {
            return null;
        }

        DirectoryLogin directoryLogin;
        try {
            directoryLogin = authenticate(auth, jaasConfiguration(), JAAS_MODULE);
        } catch (LoginException le) {
            log.debug(le.toString(), le);
            return null;
        } catch (ExternalAuthException ex) {
            log.error("LDAP login unavailable: " + ex.getMessage(), ex);
            throw ex;
        }

        try (Connection con = DBUtils.getConn()) {
            return ExternalAccountUtil.link(con, directoryLogin.user, Auth.AUTH_EXTERNAL,
                    directoryLogin.allRoles, directoryLogin.assignedRoles, DEFAULT_LDAP_PROFILE);
        }
    }

    /**
     * Why LDAP login cannot work with the current jaas.conf, for a startup warning - the
     * jaasModule entry missing, or a login module class that does not load.
     *
     * @return the problem, or null if there is none or external auth is off
     */
    public static String configurationProblem() {
        if (!externalAuthEnabled) {
            return null;
        }
        try {
            checkConfiguration(withCurrentJettyNames(jaasConfiguration()), JAAS_MODULE);
            return null;
        } catch (ExternalAuthException ex) {
            return ex.getMessage();
        }
    }

    private static Configuration jaasConfiguration() throws ExternalAuthException {
        try {
            return Configuration.getConfiguration();
        } catch (SecurityException ex) {
            throw new ExternalAuthException("could not read " + AppConfig.CONFIG_DIR + "/" + JAAS_CONF, ex);
        }
    }

    private static AppConfigurationEntry[] checkConfiguration(Configuration configuration, String jaasModule) throws ExternalAuthException {
        AppConfigurationEntry[] entries = configuration.getAppConfigurationEntry(jaasModule);
        if (entries == null || entries.length == 0) {
            throw new ExternalAuthException("jaasModule=" + jaasModule + " but " + JAAS_CONF + " has no entry by that name");
        }
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader() != null
                ? Thread.currentThread().getContextClassLoader() : ExternalAuthUtil.class.getClassLoader();
        for (AppConfigurationEntry entry : entries) {
            try {
                Class.forName(entry.getLoginModuleName(), false, classLoader);
            } catch (ClassNotFoundException ex) {
                throw new ExternalAuthException(JAAS_CONF + " entry " + jaasModule + " names login module "
                        + entry.getLoginModuleName() + ", which does not exist", ex);
            }
        }
        return entries;
    }

    /**
     * Authenticates against the given JAAS module and reads what the directory knows about
     * the user. Touches no database.
     *
     * @param auth          username and password
     * @param configuration JAAS configuration holding jaasModule
     * @param jaasModule    entry name in that configuration
     * @return what the login says about the user
     * @throws LoginException        if the directory rejected the credentials
     * @throws ExternalAuthException if the directory could not be asked
     */
    static DirectoryLogin authenticate(final Auth auth, Configuration configuration, String jaasModule)
            throws LoginException, ExternalAuthException {
        configuration = withCurrentJettyNames(configuration);
        AppConfigurationEntry[] entries = checkConfiguration(configuration, jaasModule);

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

        //connected before the login rather than after: an unreachable directory fails here,
        //whereas inside LoginContext it comes back as the same bare LoginException as a
        //wrong password
        Map<AppConfigurationEntry, LdapLoginModule> ldapModules = new HashMap<>();
        try {
            for (AppConfigurationEntry entry : entries) {
                if (LdapLoginModule.class.getName().equals(entry.getLoginModuleName())) {
                    LdapLoginModule loginModule = new LdapLoginModule();
                    try {
                        loginModule.initialize(new Subject(), callbackHandler, new HashMap<>(), entry.getOptions());
                    } catch (IllegalStateException ex) {
                        throw new ExternalAuthException("could not connect to the directory", ex);
                    }
                    ldapModules.put(entry, loginModule);
                }
            }

            LoginContext loginContext = new LoginContext(jaasModule, new Subject(), callbackHandler, configuration);
            try {
                //will throw exception if login fail
                loginContext.login();
            } catch (LoginException ex) {
                if (isDirectoryUnreachable(ex)) {
                    throw new ExternalAuthException("could not connect to the directory", ex);
                }
                throw ex;
            }

            DirectoryLogin directoryLogin = new DirectoryLogin();
            directoryLogin.user.setUsername(auth.getUsername());
            if (auth.getUsername().contains("@")) {
                directoryLogin.user.setEmail(auth.getUsername());
            }

            for (AppConfigurationEntry entry : entries) {
                LdapLoginModule loginModule = ldapModules.get(entry);
                if (loginModule != null) {
                    try {
                        readLdapUser(directoryLogin, auth.getUsername(), loginModule, entry.getOptions());
                    } catch (Exception ex) {
                        throw new ExternalAuthException("could not read the user's entry from the directory", ex);
                    }
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
        } finally {
            //closes each module's own directory connection
            for (LdapLoginModule loginModule : ldapModules.values()) {
                try {
                    loginModule.abort();
                } catch (LoginException ex) {
                    log.debug(ex.toString(), ex);
                }
            }
        }
    }

    /**
     * true if a failed login was the directory not answering rather than refusing - the JDK's
     * LdapLoginModule reports both as FailedLoginException, with the connection failure as
     * the cause
     */
    private static boolean isDirectoryUnreachable(Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof CommunicationException || t instanceof ServiceUnavailableException) {
                return true;
            }
        }
        return false;
    }

    /**
     * reads the user's roles, every role the directory knows about, and the user's name and
     * email, using the same connection settings and defaults as the LdapLoginModule entry
     */
    private static void readLdapUser(DirectoryLogin directoryLogin, String username, LdapLoginModule loginModule,
                                     Map<String, ?> options) throws Exception {

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
