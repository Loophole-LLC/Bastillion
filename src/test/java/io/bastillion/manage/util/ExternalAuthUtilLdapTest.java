/**
 * Copyright (C) 2017 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import io.bastillion.manage.model.Auth;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs the LDAP login path against a real in-memory directory, configured the way the
 * shipped jaas.conf examples are. Until this existed nothing exercised that path, and it had
 * been failing every login since the move to Java 21 and Jetty 10+: the directory accepted
 * the password, then reflection into LoginContext and LdapLoginModule threw.
 */
class ExternalAuthUtilLdapTest {

    private static final String BASE = "dc=bastillion,dc=com";
    private static final String MODULE = "ldap-test";
    private static InMemoryDirectoryServer server;

    @BeforeAll
    static void startDirectory() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
        config.addAdditionalBindCredentials("cn=admin," + BASE, "adminpw");
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default", 0));
        server = new InMemoryDirectoryServer(config);
        server.startListening();

        server.add("dn: " + BASE, "objectClass: top", "objectClass: domain", "dc: bastillion");
        server.add("dn: ou=users," + BASE, "objectClass: organizationalUnit", "ou: users");
        server.add("dn: ou=groups," + BASE, "objectClass: organizationalUnit", "ou: groups");
        server.add("dn: uid=jdoe,ou=users," + BASE, "objectClass: inetOrgPerson", "uid: jdoe",
                "cn: Jane Doe", "givenName: Jane", "sn: Doe", "mail: jane@corp.com", "userPassword: secret");
        server.add("dn: uid=other,ou=users," + BASE, "objectClass: inetOrgPerson", "uid: other",
                "cn: Other Person", "sn: Person", "userPassword: secret");
        server.add("dn: cn=web,ou=groups," + BASE, "objectClass: groupOfNames", "cn: web",
                "member: uid=jdoe,ou=users," + BASE);
        server.add("dn: cn=db,ou=groups," + BASE, "objectClass: groupOfNames", "cn: db",
                "member: uid=other,ou=users," + BASE);
    }

    @AfterAll
    static void stopDirectory() {
        server.shutDown(true);
    }

    private static Configuration configuration(String loginModule, Map<String, String> options) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return MODULE.equals(name) ? new AppConfigurationEntry[]{new AppConfigurationEntry(loginModule,
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)} : null;
            }
        };
    }

    // jaas.conf's ldap-ol-with-roles
    private static Map<String, String> jettyOptions(String forceBindingLogin) {
        Map<String, String> options = new HashMap<>();
        options.put("useLdaps", "false");
        options.put("contextFactory", "com.sun.jndi.ldap.LdapCtxFactory");
        options.put("hostname", "localhost");
        options.put("port", String.valueOf(server.getListenPort()));
        options.put("bindDn", "cn=admin," + BASE);
        options.put("bindPassword", "adminpw");
        options.put("authenticationMethod", "simple");
        options.put("forceBindingLogin", forceBindingLogin);
        options.put("userBaseDn", "ou=users," + BASE);
        options.put("userRdnAttribute", "uid");
        options.put("userIdAttribute", "uid");
        options.put("userPasswordAttribute", "userPassword");
        options.put("userObjectClass", "inetOrgPerson");
        options.put("roleBaseDn", "ou=groups," + BASE);
        options.put("roleNameAttribute", "cn");
        options.put("roleMemberAttribute", "member");
        options.put("roleObjectClass", "groupOfNames");
        return options;
    }

    private static Auth credentials(String username, String password) {
        Auth auth = new Auth();
        auth.setUsername(username);
        auth.setPassword(password);
        return auth;
    }

    @Test
    void jettyModuleReadsRolesNameAndEmail() throws Exception {
        Configuration config = configuration("org.eclipse.jetty.security.jaas.spi.LdapLoginModule", jettyOptions("false"));

        ExternalAuthUtil.DirectoryLogin login = ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE);

        assertEquals("jdoe", login.user.getUsername());
        assertEquals("Jane", login.user.getFirstNm());
        assertEquals("Doe", login.user.getLastNm());
        assertEquals("jane@corp.com", login.user.getEmail());
        assertEquals(List.of("web"), login.assignedRoles);
        assertEquals(List.of("web", "db"), login.allRoles.stream().sorted((a, b) -> b.compareTo(a)).toList());
    }

    @Test
    void jettyModuleWithBindingLogin() throws Exception {
        Configuration config = configuration("org.eclipse.jetty.security.jaas.spi.LdapLoginModule", jettyOptions("true"));

        ExternalAuthUtil.DirectoryLogin login = ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE);

        assertEquals(List.of("web"), login.assignedRoles);
    }

    @Test
    void jettyModuleRejectsWrongPassword() {
        Configuration config = configuration("org.eclipse.jetty.security.jaas.spi.LdapLoginModule", jettyOptions("false"));

        assertThrows(LoginException.class,
                () -> ExternalAuthUtil.authenticate(credentials("jdoe", "wrong"), config, MODULE));
    }

    @Test
    void preJetty12ModuleNameStillLoads() throws Exception {
        Configuration config = configuration(ExternalAuthUtil.LEGACY_LDAP_LOGIN_MODULE, jettyOptions("false"));

        ExternalAuthUtil.DirectoryLogin login = ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE);

        assertEquals(List.of("web"), login.assignedRoles);
    }

    // jaas.conf's ldap-ol
    @Test
    void jdkModuleTakesNameFromPrincipal() throws Exception {
        Map<String, String> options = new HashMap<>();
        options.put("userProvider", "ldap://localhost:" + server.getListenPort() + "/ou=users," + BASE);
        options.put("authIdentity", "uid={USERNAME},ou=users," + BASE);
        options.put("userFilter", "(&(uid={USERNAME})(objectClass=inetOrgPerson))");
        options.put("authzIdentity", "{cn}");
        options.put("useSSL", "false");
        Configuration config = configuration("com.sun.security.auth.module.LdapLoginModule", options);

        ExternalAuthUtil.DirectoryLogin login = ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE);

        assertEquals("Jane", login.user.getFirstNm());
        assertEquals("Doe", login.user.getLastNm());
        assertNull(login.assignedRoles);
        assertNull(login.allRoles);
    }

    // --- rejected credentials vs a directory that could not be asked ---
    // Both used to come back as "invalid credentials", which is how LDAP login stayed broken
    // unnoticed. Each module reports them differently, so each case is pinned down here.

    private static int closedPort() throws java.io.IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Test
    void jettyModuleWrongPasswordIsARejectionNotAnOutage() {
        for (String forceBindingLogin : List.of("false", "true")) {
            Configuration config = configuration("org.eclipse.jetty.security.jaas.spi.LdapLoginModule", jettyOptions(forceBindingLogin));

            //a LoginException, which login() treats as wrong credentials - not ExternalAuthException
            assertThrows(LoginException.class,
                    () -> ExternalAuthUtil.authenticate(credentials("jdoe", "wrong"), config, MODULE));
        }
    }

    @Test
    void jettyModuleUnreachableDirectoryIsAnOutage() throws Exception {
        Map<String, String> options = jettyOptions("false");
        options.put("port", String.valueOf(closedPort()));
        Configuration config = configuration("org.eclipse.jetty.security.jaas.spi.LdapLoginModule", options);

        assertThrows(ExternalAuthException.class,
                () -> ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE));
    }

    @Test
    void jdkModuleUnreachableDirectoryIsAnOutage() throws Exception {
        Map<String, String> options = new HashMap<>();
        options.put("userProvider", "ldap://localhost:" + closedPort() + "/ou=users," + BASE);
        options.put("authIdentity", "uid={USERNAME},ou=users," + BASE);
        options.put("useSSL", "false");
        Configuration config = configuration("com.sun.security.auth.module.LdapLoginModule", options);

        assertThrows(ExternalAuthException.class,
                () -> ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE));
    }

    @Test
    void missingLoginModuleClassIsAnOutage() {
        Configuration config = configuration("org.example.NoSuchLoginModule", jettyOptions("false"));

        ExternalAuthException ex = assertThrows(ExternalAuthException.class,
                () -> ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, MODULE));
        assertTrue(ex.getMessage().contains("org.example.NoSuchLoginModule"));
    }

    @Test
    void unknownJaasEntryIsAnOutage() {
        Configuration config = configuration("org.eclipse.jetty.security.jaas.spi.LdapLoginModule", jettyOptions("false"));

        ExternalAuthException ex = assertThrows(ExternalAuthException.class,
                () -> ExternalAuthUtil.authenticate(credentials("jdoe", "secret"), config, "no-such-entry"));
        assertTrue(ex.getMessage().contains("no-such-entry"));
    }

    @Test
    void jdkModuleRejectsWrongPassword() {
        Map<String, String> options = new HashMap<>();
        options.put("userProvider", "ldap://localhost:" + server.getListenPort() + "/ou=users," + BASE);
        options.put("authIdentity", "uid={USERNAME},ou=users," + BASE);
        options.put("useSSL", "false");
        Configuration config = configuration("com.sun.security.auth.module.LdapLoginModule", options);

        assertThrows(LoginException.class,
                () -> ExternalAuthUtil.authenticate(credentials("jdoe", "wrong"), config, MODULE));
    }
}
