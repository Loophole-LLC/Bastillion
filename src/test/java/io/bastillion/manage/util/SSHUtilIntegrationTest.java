/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.KeyPair;
import io.bastillion.manage.db.CertAuthorityDB;
import io.bastillion.manage.db.DbTestSupport;
import io.bastillion.manage.db.HostKeyDB;
import io.bastillion.manage.db.PrivateKeyDB;
import io.bastillion.manage.db.PublicKeyDB;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.db.SystemStatusDB;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.model.ApplicationKey;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.KnownHostKey;
import io.bastillion.manage.model.SchSession;
import io.bastillion.manage.model.SessionOutput;
import io.bastillion.manage.model.User;
import io.bastillion.manage.model.UserSchSessions;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

/**
 * SSHUtil against a real SSH server: an in-process Apache MINA SSHD with SFTP, on a random
 * localhost port. The unit tests around SSHUtil cover its decisions one at a time; these
 * cover what only a real handshake shows - that JSch, host key verification, the credential
 * fallbacks and the SFTP rewrite of authorized_keys actually fit together, and that each way
 * a connection fails is reported as the status the systems screen expects.
 * <p>
 * Everything that would reach the database is stubbed. Host keys go through a small
 * in-memory store standing in for the host_key table, so the first-sighting and changed-key
 * paths run through {@link HostKeyVerifier} unmodified.
 */
class SSHUtilIntegrationTest {

    private static final String LOGIN = "deploy";
    private static final String PASSWORD = "correct horse";

    @TempDir
    Path home;

    private SshServer sshd;
    private final AtomicInteger passwordAttempts = new AtomicInteger();
    private volatile PublicKey trustedUserCa;

    /** host_key rows by host:port:type */
    private final Map<String, KnownHostKey> hostKeys = new ConcurrentHashMap<>();

    private ApplicationKey appKey;
    private CertAuthority userCa;

    private MockedStatic<PrivateKeyDB> privateKeyDb;
    private MockedStatic<HostKeyDB> hostKeyDb;
    private MockedStatic<PublicKeyDB> publicKeyDb;
    private MockedStatic<SystemDB> systemDb;
    private MockedStatic<SystemStatusDB> systemStatusDb;
    private MockedStatic<UserDB> userDb;
    private MockedStatic<CertAuthorityDB> certAuthorityDb;

    @BeforeEach
    void startServer() throws Exception {
        Files.createDirectories(home.resolve(".ssh"));

        sshd = SshServer.setUpDefaultServer();
        sshd.setHost("127.0.0.1");
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPasswordAuthenticator((username, password, session) -> {
            passwordAttempts.incrementAndGet();
            return LOGIN.equals(username) && PASSWORD.equals(password);
        });
        sshd.setKeyboardInteractiveAuthenticator(null);
        sshd.setPublickeyAuthenticator(this::acceptsKey);
        sshd.setShellFactory(channel -> new EchoShell());
        sshd.setSubsystemFactories(List.of(new SftpSubsystemFactory()));
        sshd.setFileSystemFactory(new VirtualFileSystemFactory(home));
        sshd.start();

        appKey = applicationKey();
        userCa = certAuthority();

        privateKeyDb = mockStatic(PrivateKeyDB.class);
        privateKeyDb.when(PrivateKeyDB::getApplicationKey).thenReturn(appKey);

        hostKeyDb = mockStatic(HostKeyDB.class);
        hostKeyDb.when(() -> HostKeyDB.getHostKey(anyString(), anyInt(), anyString()))
                .thenAnswer(inv -> hostKeys.get(inv.getArgument(0) + ":" + inv.getArgument(1) + ":" + inv.getArgument(2)));
        hostKeyDb.when(() -> HostKeyDB.insertHostKey(anyString(), anyInt(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    KnownHostKey known = new KnownHostKey();
                    known.setHost(inv.getArgument(0));
                    known.setPort(inv.getArgument(1));
                    known.setType(inv.getArgument(2));
                    known.setPublicKey(inv.getArgument(3));
                    known.setFingerprint(inv.getArgument(4));
                    known.setStatus(inv.getArgument(5));
                    hostKeys.put(known.getHost() + ":" + known.getPort() + ":" + known.getType(), known);
                    return null;
                });
        hostKeyDb.when(HostKeyDB::getRevokedHostKeys).thenReturn(List.of());

        publicKeyDb = mockStatic(PublicKeyDB.class);
        systemDb = mockStatic(SystemDB.class);
        systemStatusDb = mockStatic(SystemStatusDB.class);
        userDb = mockStatic(UserDB.class);
        certAuthorityDb = mockStatic(CertAuthorityDB.class);
        certAuthorityDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(userCa);
        certAuthorityDb.when(() -> CertAuthorityDB.nextSerial(anyString())).thenReturn(1L);
    }

    @AfterEach
    void stopServer() throws Exception {
        for (MockedStatic<?> mock : new MockedStatic<?>[]{privateKeyDb, hostKeyDb, publicKeyDb, systemDb,
                systemStatusDb, userDb, certAuthorityDb}) {
            if (mock != null) {
                mock.close();
            }
        }
        sshd.stop(true);
    }

    /**
     * Public key authentication the way sshd does it: a plain key must be listed in
     * ~/.ssh/authorized_keys as it stands at that moment - so a key Bastillion installed is
     * honoured by the next connection, as on a real host - and a certificate must be signed by
     * the TrustedUserCAKeys authority and name the account being logged into. MINA itself
     * checks the certificate's signature, type and validity before asking.
     */
    private boolean acceptsKey(String username, PublicKey key, ServerSession session) {
        if (!LOGIN.equals(username)) {
            return false;
        }
        try {
            if (key instanceof OpenSshCertificate certificate) {
                return trustedUserCa != null
                        && KeyUtils.compareKeys(trustedUserCa, certificate.getCaPubKey())
                        && certificate.getPrincipals().contains(username);
            }
            Path authorizedKeys = home.resolve(".ssh/authorized_keys");
            if (!Files.exists(authorizedKeys)) {
                return false;
            }
            for (AuthorizedKeyEntry entry : AuthorizedKeyEntry.readAuthorizedKeys(authorizedKeys)) {
                PublicKey listed = entry.resolvePublicKey(session, PublicKeyEntryResolver.IGNORING);
                if (listed != null && KeyUtils.compareKeys(listed, key)) {
                    return true;
                }
            }
            return false;
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String publicKeyLine(java.security.KeyPair kp, String comment) throws Exception {
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(
                OpenSSHKeyUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded())) + " " + comment;
    }

    private static ApplicationKey applicationKey() throws Exception {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        ApplicationKey key = new ApplicationKey();
        key.setId(1L);
        key.setPublicKey(publicKeyLine(kp, "bastillion@global_key"));
        key.setPrivateKey(OpenSSHKeyUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519));
        return key;
    }

    private static CertAuthority certAuthority() throws Exception {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        CertAuthority ca = new CertAuthority();
        ca.setType(CertAuthority.USER_CA);
        ca.setPrivateKey(OpenSSHKeyUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519));
        ca.setPublicKey(publicKeyLine(kp, "bastillion-user-ca"));
        return ca;
    }

    private void trustUserCa() throws Exception {
        trustedUserCa = AuthorizedKeyEntry.parseAuthorizedKeyEntry(userCa.getPublicKey())
                .resolvePublicKey(null, PublicKeyEntryResolver.IGNORING);
    }

    private HostSystem system() {
        HostSystem hostSystem = new HostSystem();
        hostSystem.setId(7L);
        hostSystem.setDisplayNm("integration");
        hostSystem.setHost("127.0.0.1");
        hostSystem.setPort(sshd.getPort());
        hostSystem.setUser(LOGIN);
        hostSystem.setAuthorizedKeys("~/.ssh/authorized_keys");
        return hostSystem;
    }

    private String authorizedKeys() throws Exception {
        return Files.readString(home.resolve(".ssh/authorized_keys"));
    }

    @Test
    void registeringWithAPasswordInstallsTheApplicationKeySoTheNextConnectionNeedsNone() throws Exception {
        HostSystem first = SSHUtil.authAndAddPubKey(system(), null, PASSWORD);

        assertEquals(HostSystem.SUCCESS_STATUS, first.getStatusCd(), first.getErrorMsg());
        assertEquals(HostSystem.AUTH_METHOD_PASSWORD, first.getLastAuthMethod());
        assertTrue(authorizedKeys().contains(appKey.getPublicKey()), authorizedKeys());

        int attemptsBefore = passwordAttempts.get();
        HostSystem second = SSHUtil.authAndAddPubKey(system(), null, null);

        assertEquals(HostSystem.SUCCESS_STATUS, second.getStatusCd(), second.getErrorMsg());
        assertEquals(HostSystem.AUTH_METHOD_KEY, second.getLastAuthMethod());
        assertEquals(attemptsBefore, passwordAttempts.get(), "the key alone should have been enough");
    }

    @Test
    void trustsTheHostKeyOnFirstSightAndKeepsUsingTheRecordedOne() {
        SSHUtil.authAndAddPubKey(system(), null, PASSWORD);

        assertEquals(1, hostKeys.size());
        KnownHostKey recorded = hostKeys.values().iterator().next();
        assertEquals(KnownHostKey.TRUSTED, recorded.getStatus());
        assertEquals("127.0.0.1", recorded.getHost());
        assertEquals(sshd.getPort(), recorded.getPort());

        HostSystem again = SSHUtil.authAndAddPubKey(system(), null, PASSWORD);
        assertEquals(HostSystem.SUCCESS_STATUS, again.getStatusCd(), again.getErrorMsg());
        assertEquals(1, hostKeys.size());
    }

    @Test
    void aChangedHostKeyIsRefusedBeforeAnyCredentialIsSent() throws Exception {
        SSHUtil.authAndAddPubKey(system(), null, PASSWORD);
        KnownHostKey recorded = hostKeys.values().iterator().next();
        // what the host_key row would hold had a different machine answered first
        recorded.setPublicKey(Base64.getEncoder().encodeToString(
                OpenSSHKeyUtil.encodeSSHPublicKey("ssh-ed25519", java.security.KeyPairGenerator
                        .getInstance("Ed25519").generateKeyPair().getPublic().getEncoded())));
        int attemptsBefore = passwordAttempts.get();

        HostSystem result = SSHUtil.authAndAddPubKey(system(), null, PASSWORD);

        assertEquals(HostSystem.HOST_KEY_FAIL_STATUS, result.getStatusCd());
        assertEquals(attemptsBefore, passwordAttempts.get(), "the password must never reach a host whose key changed");
        hostKeyDb.verify(() -> HostKeyDB.markChanged(anyString(), anyInt(), anyString(), anyString(), anyString()));
    }

    @Test
    void aWrongPasswordIsReportedAsAnAuthenticationFailure() {
        HostSystem result = SSHUtil.authAndAddPubKey(system(), null, "wrong");

        assertEquals(HostSystem.AUTH_FAIL_STATUS, result.getStatusCd(), result.getErrorMsg());
    }

    @Test
    void nothingListeningIsReportedAsAGenericFailureNotAnAuthFailure() throws Exception {
        HostSystem hostSystem = system();
        try (ServerSocket socket = new ServerSocket(0)) {
            hostSystem.setPort(socket.getLocalPort());
        }

        HostSystem result = SSHUtil.authAndAddPubKey(hostSystem, null, PASSWORD);

        assertEquals(HostSystem.GENERIC_FAIL_STATUS, result.getStatusCd(), result.getErrorMsg());
    }

    @Test
    void manageModeReplacesAuthorizedKeysWithTheAssignedKeysAndLeavesNoStagedFile() throws Exception {
        Files.writeString(home.resolve(".ssh/authorized_keys"), publicKeyLine(
                java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair(), "someone@elsewhere") + "\n");
        String assigned = publicKeyLine(java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair(),
                "alice's laptop");
        publicKeyDb.when(() -> PublicKeyDB.getPublicKeysForSystem(7L)).thenReturn(List.of(assigned));

        HostSystem result = SSHUtil.authAndAddPubKey(system(), null, PASSWORD);

        assertEquals(HostSystem.SUCCESS_STATUS, result.getStatusCd(), result.getErrorMsg());
        assertEquals(assigned + "\n" + appKey.getPublicKey() + "\n", authorizedKeys());
        try (var files = Files.list(home.resolve(".ssh"))) {
            assertEquals(List.of(home.resolve(".ssh/authorized_keys")), files.toList());
        }
    }

    /**
     * Disabling a key, assigning a profile and the refresh timer each start their own refresh
     * thread, so two writes to one host at once is ordinary. Staged under one shared name,
     * the loser's rename found its staged file already moved into place, fell back to
     * removing the original - and then had nothing to rename, leaving the host with no
     * authorized_keys at all, application key included.
     */
    @Test
    void concurrentWritesToOneHostNeverLeaveItWithoutAuthorizedKeys() throws Exception {
        int writers = 4;
        List<com.jcraft.jsch.Session> sessions = new java.util.ArrayList<>();
        for (int i = 0; i < writers; i++) {
            com.jcraft.jsch.Session session = new com.jcraft.jsch.JSch().getSession(LOGIN, "127.0.0.1", sshd.getPort());
            session.setPassword(PASSWORD);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(10000);
            sessions.add(session);
        }
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(writers);
        try {
            for (int round = 0; round < 25; round++) {
                java.util.concurrent.CyclicBarrier start = new java.util.concurrent.CyclicBarrier(writers);
                List<java.util.concurrent.Future<?>> writes = new java.util.ArrayList<>();
                for (int i = 0; i < writers; i++) {
                    com.jcraft.jsch.Session session = sessions.get(i);
                    String contents = "writer " + i + "\n" + appKey.getPublicKey() + "\n";
                    writes.add(pool.submit(() -> {
                        start.await();
                        AuthorizedKeysUtil.writeAuthorizedKeys(session, ".ssh/authorized_keys", contents);
                        return null;
                    }));
                }
                for (java.util.concurrent.Future<?> write : writes) {
                    write.get();
                }

                assertTrue(Files.exists(home.resolve(".ssh/authorized_keys")), "authorized_keys gone after round " + round);
                assertTrue(authorizedKeys().endsWith(appKey.getPublicKey() + "\n"), authorizedKeys());
                try (var files = Files.list(home.resolve(".ssh"))) {
                    assertEquals(List.of(home.resolve(".ssh/authorized_keys")), files.toList());
                }
            }
        } finally {
            pool.shutdownNow();
            sessions.forEach(com.jcraft.jsch.Session::disconnect);
        }
    }

    @Test
    void opensATerminalWhoseOutputReachesTheSessionBuffer() throws Exception {
        long sessionId = 9_100_001L;
        Map<Long, UserSchSessions> userSessions = new ConcurrentHashMap<>();

        HostSystem result = SSHUtil.openSSHTermOnSystem(null, PASSWORD, 1L, sessionId, system(), userSessions);

        assertEquals(HostSystem.SUCCESS_STATUS, result.getStatusCd(), result.getErrorMsg());
        SchSession schSession = userSessions.get(sessionId).getSchSessionMap().get(result.getInstanceId());
        assertNotNull(schSession);
        try (Connection con = DbTestSupport.newConnection()) {
            try (PreparedStatement stmt = con.prepareStatement("insert into session_log (id, username) values (?, 'alice')")) {
                stmt.setLong(1, sessionId);
                stmt.execute();
            }
            User user = new User();
            user.setId(1L);
            user.setUsername("alice");

            schSession.getCommander().print("hello from bastillion\n");

            StringBuilder seen = new StringBuilder();
            long deadline = System.currentTimeMillis() + 10_000;
            while (!seen.toString().contains("hello from bastillion") && System.currentTimeMillis() < deadline) {
                for (SessionOutput output : SessionOutputUtil.getOutput(con, sessionId, user)) {
                    seen.append(output.getOutput());
                }
                Thread.sleep(50);
            }
            assertTrue(seen.toString().contains("hello from bastillion"), seen.toString());
        } finally {
            schSession.getChannel().disconnect();
            schSession.getSession().disconnect();
            SessionOutputUtil.removeUserSession(sessionId);
        }
        systemStatusDb.verify(() -> SystemStatusDB.updateSystemStatus(any(HostSystem.class), anyLong()));
    }

    /**
     * createTerms prompts for a password only on AUTHFAIL; from 4.0.0 to 6.0.2 a terminal to
     * a host without the application key installed came back GENERICFAIL instead, and the
     * user got an error dialog where the password prompt should have been.
     */
    @Test
    void aTerminalToAHostWithoutTheKeyAsksForAPasswordAndIsNotLeftInTheSessionMap() throws Exception {
        long sessionId = 9_100_002L;
        Map<Long, UserSchSessions> userSessions = new ConcurrentHashMap<>();

        HostSystem result = SSHUtil.openSSHTermOnSystem(null, null, 1L, sessionId, system(), userSessions);

        assertEquals(HostSystem.AUTH_FAIL_STATUS, result.getStatusCd(), result.getErrorMsg());
        assertTrue(userSessions.get(sessionId).getSchSessionMap().isEmpty());
    }

    @Test
    void aTerminalWithAWrongPasswordAsksAgain() throws Exception {
        HostSystem result = SSHUtil.openSSHTermOnSystem(null, "wrong", 1L, 9_100_003L, system(),
                new ConcurrentHashMap<>());

        assertEquals(HostSystem.AUTH_FAIL_STATUS, result.getStatusCd(), result.getErrorMsg());
    }

    @Test
    void anEncryptedApplicationKeyWithoutItsPassphraseAsksForThePassphrase() throws Exception {
        encryptApplicationKey("key passphrase");
        Files.writeString(home.resolve(".ssh/authorized_keys"), appKey.getPublicKey() + "\n");

        HostSystem register = SSHUtil.authAndAddPubKey(system(), null, null);
        HostSystem terminal = SSHUtil.openSSHTermOnSystem(null, null, 1L, 9_100_004L, system(),
                new ConcurrentHashMap<>());

        assertEquals(HostSystem.PUBLIC_KEY_FAIL_STATUS, register.getStatusCd(), register.getErrorMsg());
        assertEquals(HostSystem.PUBLIC_KEY_FAIL_STATUS, terminal.getStatusCd(), terminal.getErrorMsg());
    }

    @Test
    void anEncryptedApplicationKeyConnectsOnceThePassphraseIsGiven() throws Exception {
        encryptApplicationKey("key passphrase");
        Files.writeString(home.resolve(".ssh/authorized_keys"), appKey.getPublicKey() + "\n");

        HostSystem result = SSHUtil.authAndAddPubKey(system(), "key passphrase", null);

        assertEquals(HostSystem.SUCCESS_STATUS, result.getStatusCd(), result.getErrorMsg());
        assertEquals(HostSystem.AUTH_METHOD_KEY, result.getLastAuthMethod());
    }

    /**
     * Replaces the application key with an RSA key encrypted under the given passphrase,
     * without storing the passphrase - an application key whose passphrase the operator
     * chose not to keep, so it has to be typed at connect time.
     */
    private void encryptApplicationKey(String passphrase) throws Exception {
        KeyPair kp = KeyPair.genKeyPair(new com.jcraft.jsch.JSch(), KeyPair.RSA, 2048);
        java.io.ByteArrayOutputStream privateKey = new java.io.ByteArrayOutputStream();
        kp.writePrivateKey(privateKey, passphrase.getBytes(StandardCharsets.UTF_8));
        java.io.ByteArrayOutputStream publicKey = new java.io.ByteArrayOutputStream();
        kp.writePublicKey(publicKey, "bastillion@global_key");
        appKey.setPrivateKey(privateKey.toString(StandardCharsets.UTF_8));
        appKey.setPublicKey(publicKey.toString(StandardCharsets.UTF_8).trim());
        appKey.setPassphrase(null);
    }

    @Test
    void certificateTestPassesOnAHostThatTrustsTheAuthority() throws Exception {
        trustUserCa();

        SSHUtil.CertificateTestResult result = SSHUtil.testCertificateAuth(system(), "alice");

        assertTrue(result.ok(), result.message());
        assertEquals(0, passwordAttempts.get());
    }

    @Test
    void certificateTestFailsOnAHostThatDoesNotTrustTheAuthorityEvenWithTheKeyInstalled() throws Exception {
        // The application key is already in authorized_keys - exactly the host where a naive
        // test would succeed on the key and wrongly report the host ready for certificates.
        Files.writeString(home.resolve(".ssh/authorized_keys"), appKey.getPublicKey() + "\n");

        SSHUtil.CertificateTestResult result = SSHUtil.testCertificateAuth(system(), "alice");

        assertFalse(result.ok(), result.message());
        assertTrue(result.message().contains("TrustedUserCAKeys"), result.message());
    }

    /** A shell that echoes back whatever it is sent, standing in for a login shell. */
    private static final class EchoShell implements Command, Runnable {

        private InputStream in;
        private OutputStream out;
        private ExitCallback exitCallback;
        private Thread thread;

        @Override
        public void setInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void setErrorStream(OutputStream err) {
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            this.exitCallback = callback;
        }

        @Override
        public void start(ChannelSession channel, Environment env) {
            thread = new Thread(this, "echo-shell");
            thread.setDaemon(true);
            thread.start();
        }

        @Override
        public void run() {
            byte[] buffer = new byte[1024];
            try {
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(new String(buffer, 0, read, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8));
                    out.flush();
                }
            } catch (Exception ignored) {
                // channel closed
            } finally {
                exitCallback.onExit(0);
            }
        }

        @Override
        public void destroy(ChannelSession channel) {
            if (thread != null) {
                thread.interrupt();
            }
        }
    }
}
