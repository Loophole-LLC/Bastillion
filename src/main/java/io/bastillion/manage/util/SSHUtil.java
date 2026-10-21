/**
 * Copyright (C) 2013 Loophole, LLC
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.*;
import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.db.*;
import io.bastillion.manage.model.*;
import io.bastillion.manage.task.SecureShellTask;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.*;

/**
 * SSH utility class used to create public/private key for system and distribute authorized key files
 */
public class SSHUtil {

    public static final String PRIVATE_KEY = "privateKey";
    public static final String PUBLIC_KEY = "publicKey";
    private static final Logger log = LoggerFactory.getLogger(SSHUtil.class);
    /**
     * True when Bastillion distributes user public keys to hosts and owns their
     * authorized_keys files - {@link KeyManagement.Mode#MANAGE}. Gates the refresh timer, the
     * distribution loops below, and the "Manage SSH Keys" screens (referenced from the
     * navigation and menu templates), all of which have nothing to do in the other modes.
     * See {@link KeyManagement} for the full three-way setting.
     */
    public static final boolean keyManagementEnabled = KeyManagement.distributesUserKeys();

    public static final String KEY_PATH = AppConfig.CONFIG_DIR + "keydb";
    public static final String KEY_TYPE = AppConfig.getProperty("sshKeyType");
    public static final int KEY_LENGTH = resolveKeyLength(KEY_TYPE, AppConfig.getProperty("sshKeyLength"));

    /** Documented default for rsa when sshKeyLength does not give a usable one. */
    static final int RSA_DEFAULT_LENGTH = 4096;
    /** The only curve sizes ecdsa accepts. */
    private static final Set<Integer> ECDSA_CURVE_SIZES = Set.of(256, 384, 521);

    /**
     * The key size to generate, given the configured type and length.
     * <p>
     * sshKeyLength ships as 256, which is a curve size for ecdsa and ignored by
     * ed25519/ed448 - but it is not a usable RSA modulus, so sshKeyType=rsa on its own used to
     * fail key generation outright and take the application down with it on first startup.
     * Both the bundled config and the README already describe rsa as defaulting to 4096, so a
     * length that cannot work for the chosen type falls back to the documented default for it
     * rather than being passed through to fail. Substitutions are logged: quietly generating a
     * key of a different size than asked for would be worse than the original crash.
     */
    static int resolveKeyLength(String keyType, String configuredLength) {
        Integer requested = StringUtils.isNumeric(configuredLength)
                ? Integer.valueOf(Integer.parseInt(configuredLength)) : null;
        String type = StringUtils.trimToEmpty(keyType).toLowerCase();

        if ("rsa".equals(type)) {
            if (requested != null && requested >= 1024) {
                return requested;
            }
            log.error("sshKeyLength={} cannot be used for an RSA key; generating {} bits instead. "
                    + "Set sshKeyLength explicitly to choose.", configuredLength, RSA_DEFAULT_LENGTH);
            return RSA_DEFAULT_LENGTH;
        }
        if ("ecdsa".equals(type)) {
            if (requested != null && ECDSA_CURVE_SIZES.contains(requested)) {
                return requested;
            }
            log.error("sshKeyLength={} is not an ECDSA curve size ({}); generating 256 instead.",
                    configuredLength, ECDSA_CURVE_SIZES);
            return 256;
        }
        // ed25519 and ed448 have one size each and ignore this value.
        return requested != null ? requested : RSA_DEFAULT_LENGTH;
    }

    public static final String DEFAULT_USER_KEY_TYPE = AppConfig.getProperty("defaultUserKeyType", "ed25519");
    public static final boolean ALLOW_USER_KEY_TYPE_SELECTION =
            "true".equals(AppConfig.getProperty("allowUserKeyTypeSelection", "false"));

    public static final String PVT_KEY = KEY_PATH + "/id_" + KEY_TYPE;
    public static final String PUB_KEY = PVT_KEY + ".pub";

    public static final int SERVER_ALIVE_INTERVAL = StringUtils.isNumeric(AppConfig.getProperty("serverAliveInterval"))
            ? Integer.parseInt(AppConfig.getProperty("serverAliveInterval")) * 1000 : 60 * 1000;
    public static final int SESSION_TIMEOUT = 60000;
    public static final int CHANNEL_TIMEOUT = 60000;

    private SSHUtil() {}

    // --- Key Accessors ---

    public static String getPublicKey() throws IOException {
        String publicKey = PUB_KEY;
        if (StringUtils.isNotEmpty(AppConfig.getProperty(PRIVATE_KEY)) &&
                StringUtils.isNotEmpty(AppConfig.getProperty(PUBLIC_KEY))) {
            publicKey = AppConfig.getProperty(PUBLIC_KEY);
        }
        return FileUtils.readFileToString(new File(publicKey), StandardCharsets.UTF_8);
    }

    public static String getPrivateKey() throws IOException {
        String privateKey = PVT_KEY;
        if (StringUtils.isNotEmpty(AppConfig.getProperty(PRIVATE_KEY)) &&
                StringUtils.isNotEmpty(AppConfig.getProperty(PUBLIC_KEY))) {
            privateKey = AppConfig.getProperty(PRIVATE_KEY);
        }
        return FileUtils.readFileToString(new File(privateKey), StandardCharsets.UTF_8);
    }

    // --- Key Generation ---

    public static String keyGen() throws ConfigurationException, JSchException, IOException, GeneralSecurityException, InterruptedException {
        Map<String, String> replaceMap = new HashMap<>();
        replaceMap.put("randomPassphrase", UUID.randomUUID().toString());
        String passphrase = AppConfig.getProperty("defaultSSHPassphrase", replaceMap);
        AppConfig.updateProperty("defaultSSHPassphrase", "${randomPassphrase}");
        return keyGen(passphrase);
    }

    public static void deleteGenSSHKeys() throws IOException {
        deletePvtGenSSHKey();
        File pub = new File(PUB_KEY);
        if (pub.exists()) FileUtils.forceDelete(pub);
    }

    public static void deletePvtGenSSHKey() throws IOException {
        File pvt = new File(PVT_KEY);
        if (pvt.exists()) FileUtils.forceDelete(pvt);
    }

    public static String keyGen(String passphrase) throws IOException, JSchException, InterruptedException, GeneralSecurityException {
        FileUtils.forceMkdir(new File(KEY_PATH));
        deleteGenSSHKeys();

        if (StringUtils.isEmpty(AppConfig.getProperty(PRIVATE_KEY)) ||
                StringUtils.isEmpty(AppConfig.getProperty(PUBLIC_KEY))) {

            Path tmpDir = Files.createTempDirectory("bastillion_keygen_" + KEY_TYPE + "_");
            Path tmpPvt = tmpDir.resolve("id_" + KEY_TYPE);
            Path tmpPub = tmpDir.resolve("id_" + KEY_TYPE + ".pub");

            int type = KeyPair.ED25519;
            if ("rsa".equalsIgnoreCase(KEY_TYPE)) type = KeyPair.RSA;
            else if ("ecdsa".equalsIgnoreCase(KEY_TYPE)) type = KeyPair.ECDSA;
            else if ("ed448".equalsIgnoreCase(KEY_TYPE)) type = KeyPair.ED448;

            String comment = "bastillion@global_key";
            JSch jsch = new JSch();
            KeyPair keyPair = KeyPair.genKeyPair(jsch, type, KEY_LENGTH);

            if (type == KeyPair.RSA || type == KeyPair.ECDSA) {
                keyPair.writePublicKey(tmpPub.toString(), comment);
                keyPair.writePrivateKey(tmpPvt.toString(),
                        StringUtils.isNotBlank(passphrase) ? passphrase.getBytes(StandardCharsets.UTF_8) : null);
                log.info("Generated {} keypair with passphrase", KEY_TYPE);
            } else {
                log.info("Generating unencrypted OpenSSH-format {} keypair", KEY_TYPE);
                java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(
                        KEY_TYPE.equalsIgnoreCase("ed448") ? "Ed448" : "Ed25519");
                java.security.KeyPair newPair = kpg.generateKeyPair();

                String opensshPEM = OpenSSHKeyUtil.buildOpenSSHPrivateKey(newPair, type);
                Files.writeString(tmpPvt, opensshPEM, StandardCharsets.US_ASCII);

                String publicKeyContent = OpenSSHKeyUtil.generateOpenSSHPublicKey(newPair, comment, type);
                Files.writeString(tmpPub, publicKeyContent, StandardCharsets.UTF_8);

                passphrase = "";
                log.info("Generated {} keypair without passphrase", KEY_TYPE);
            }

            Files.move(tmpPvt, Path.of(PVT_KEY), StandardCopyOption.REPLACE_EXISTING);
            Files.move(tmpPub, Path.of(PUB_KEY), StandardCopyOption.REPLACE_EXISTING);
            try { Files.deleteIfExists(tmpDir); } catch (Exception ignored) {}

            setFilePerms(PVT_KEY);
            setFilePerms(PUB_KEY);

            log.info("Generated {} SSH key — fingerprint: {}", KEY_TYPE, keyPair.getFingerPrint());
            keyPair.dispose();
        }
        return passphrase;
    }

    private static void setFilePerms(String path) {
        try {
            File f = new File(path);
            f.setReadable(false, false);
            f.setWritable(false, false);
            f.setExecutable(false, false);
            f.setReadable(true, true);
            f.setWritable(true, true);
        } catch (Exception ignored) {}
    }

    public static HostSystem pushUpload(HostSystem hostSystem, Session session, String source, String destination) {
        hostSystem.setStatusCd(HostSystem.SUCCESS_STATUS);
        Channel channel = null;
        ChannelSftp c = null;
        try (FileInputStream file = new FileInputStream(source)) {
            channel = session.openChannel("sftp");
            channel.connect(CHANNEL_TIMEOUT);
            c = (ChannelSftp) channel;
            destination = destination.replaceAll("~\\/|~", "");
            c.put(file, destination);
        } catch (Exception ex) {
            log.info(ex.toString(), ex);
            recordFailure(hostSystem, ex);
        }
        if (c != null) c.exit();
        if (channel != null) channel.disconnect();
        return hostSystem;
    }

    public static HostSystem openSSHTermOnSystem(String passphrase, String password, Long userId, Long sessionId,
                                                 HostSystem hostSystem, Map<Long, UserSchSessions> userSessionMap)
            throws SQLException, GeneralSecurityException {

        JSch jsch = new JSch();

        // Reserve the instance id up front, atomically, before the slow SSH handshake below.
        // The client can fire off several createSession.ktrl requests for the same Bastillion
        // session concurrently (e.g. "duplicate session"), so computing the next free id and
        // inserting into the map used to be two separate steps with a gap between them wide
        // enough for the handshake to fit in - two concurrent requests could both compute the
        // same id, and the second insert would silently overwrite the first terminal's session.
        // computeIfAbsent + synchronizing the id lookup/reservation on the per-session map
        // closes both that race and the equivalent one on userSessionMap itself.
        UserSchSessions userSchSessions = userSessionMap.computeIfAbsent(sessionId, ignored -> new UserSchSessions());
        SchSession schSession = new SchSession();
        schSession.setUserId(userId);
        hostSystem.setStatusCd(HostSystem.SUCCESS_STATUS);
        schSession.setHostSystem(hostSystem);
        int instanceId = reserveNextInstanceId(userSchSessions, schSession);
        hostSystem.setInstanceId(instanceId);

        try {
            ApplicationKey appKey = PrivateKeyDB.getApplicationKey();
            if (StringUtils.isBlank(passphrase)) passphrase = appKey.getPassphrase();
            if (passphrase == null) passphrase = "";

            String singleCredential = addApplicationIdentity(jsch, appKey, passphrase, hostSystem, usernameFor(userId));

            Session session = jsch.getSession(hostSystem.getUser(), hostSystem.getHost(), hostSystem.getPort());
            if (StringUtils.isNotBlank(password)) session.setPassword(password.getBytes(StandardCharsets.UTF_8));
            applyHostKeyVerification(jsch, session);
            session.setConfig("PreferredAuthentications", "publickey,keyboard-interactive,password");
            session.setServerAliveInterval(SERVER_ALIVE_INTERVAL);
            AcceptedAuthMethodLogger authMethodLogger = new AcceptedAuthMethodLogger(session.getLogger());
            session.setLogger(authMethodLogger);
            session.connect(SESSION_TIMEOUT);

            recordAuthMethod(hostSystem, authMethodFor(singleCredential,
                    authMethodLogger.acceptedMethod(), authMethodLogger.acceptedAlgorithm()));

            ChannelShell channel = (ChannelShell) session.openChannel("shell");
            channel.setPtyType("xterm");
            InputStream outFromChannel = channel.getInputStream();
            SessionOutput sessionOutput = new SessionOutput(sessionId, hostSystem);
            new Thread(new SecureShellTask(sessionOutput, outFromChannel)).start();

            OutputStream inputToChannel = channel.getOutputStream();
            PrintStream commander = new PrintStream(inputToChannel, true, StandardCharsets.UTF_8);
            channel.connect();

            schSession.setSession(session);
            schSession.setChannel(channel);
            schSession.setCommander(commander);
            schSession.setInputToChannel(inputToChannel);
            schSession.setOutFromChannel(outFromChannel);

            AuthorizedKeysUtil.addPubKey(hostSystem, session, appKey.getPublicKey());
        } catch (Exception ex) {
            log.info(ex.toString(), ex);
            recordFailure(hostSystem, ex);
        }

        if (!hostSystem.getStatusCd().equals(HostSystem.SUCCESS_STATUS)) {
            userSchSessions.getSchSessionMap().remove(instanceId);
        }
        SystemStatusDB.updateSystemStatus(hostSystem, userId);
        SystemDB.updateSystem(hostSystem);
        return hostSystem;
    }

    /**
     * Smallest instance id not already in use, starting at 1 - mirrors the client-side
     * getNextInstanceId() in secure_shell.html so ids line up under normal (non-racing) use.
     * Caller is responsible for synchronizing this lookup with the reservation put().
     */
    private static int getNextInstanceId(Map<Integer, SchSession> schSessionMap) {
        int instanceId = 1;
        while (schSessionMap.containsKey(instanceId)) {
            instanceId++;
        }
        return instanceId;
    }

    /**
     * Atomically finds the next free instance id for userSchSessions and inserts schSession
     * under it, so two concurrent callers (e.g. clicking "duplicate session" on the same
     * Bastillion session) can never be handed the same id. Package-private so the concurrency
     * guarantee itself can be unit tested without a real SSH handshake.
     */
    static int reserveNextInstanceId(UserSchSessions userSchSessions, SchSession schSession) {
        synchronized (userSchSessions) {
            int instanceId = getNextInstanceId(userSchSessions.getSchSessionMap());
            userSchSessions.getSchSessionMap().put(instanceId, schSession);
            return instanceId;
        }
    }

    /**
     * Points a session at Bastillion's own known_hosts ({@link HostKeyVerifier}) and turns on
     * strict checking, so JSch aborts the handshake when verification refuses a key.
     * <p>
     * {@code StrictHostKeyChecking=no} - what both of these sessions used to set
     * unconditionally - does not downgrade host key checking to a warning, it skips it: the
     * key a managed system presents was never compared against anything. That is the one
     * check standing between a bastion and handing the application private key, and on
     * authentication fallback a user's password or key passphrase, to whatever happens to
     * answer on that address.
     */
    private static void applyHostKeyVerification(JSch jsch, Session session) {
        if (!HostKeyVerifier.isEnabled()) {
            // Explicitly opted out via hostKeyVerification=off.
            session.setConfig("StrictHostKeyChecking", "no");
            return;
        }
        jsch.setHostKeyRepository(new HostKeyVerifier(jsch));
        session.setConfig("StrictHostKeyChecking", "yes");
    }

    /**
     * Registers the application key as the identity for this session, as a certificate when
     * {@code sshCertificateAuth} is on and as a bare public key otherwise.
     * <p>
     * JSch needs no special call for the certificate case: its four-argument
     * {@code addIdentity} inspects the bytes in the public key slot, and routes to its
     * certificate-aware identity when it finds a certificate there rather than a plain key.
     * The private key is the same either way - a certificate attests to a key, it does not
     * replace one.
     * <p>
     * With certificates on, the plain key is offered as well, as a second identity behind the
     * certificate. Offering only the certificate meant that turning sshCertificateAuth on cut
     * off every host that had not had TrustedUserCAKeys configured yet - including hosts with
     * the application key already sitting in their authorized_keys, which authenticated
     * perfectly well the moment before. That strands an operator: the refresh timer is how
     * Bastillion reaches a host to manage it, so the connection needed to roll the CA out is
     * the one that breaks first. Offering both makes the rollout incremental - a host takes
     * the certificate once it trusts the CA, and keeps working on its key until then - and
     * grants no trust that was not already there, the key being in authorized_keys already.
     * <p>
     * Returns the credential to attribute a publickey success to when only one was offered,
     * and null when both were, in which case nothing but the accepted algorithm can tell them
     * apart (see {@link #authMethodFor}).
     */
    private static String addApplicationIdentity(JSch jsch, ApplicationKey appKey, String passphrase,
                                                 HostSystem hostSystem, String username) throws JSchException {
        String certificate = SshCertificateAuth.certificateFor(hostSystem, username);
        byte[] privateKey = appKey.getPrivateKey().trim().getBytes();

        if (certificate != null) {
            // Added first, so JSch offers it first and a host that trusts the CA never falls
            // back to the key. JSch keys identities by public key blob rather than by name,
            // so the certificate and the key it attests to are two distinct identities.
            jsch.addIdentity(appKey.getId() + "-cert", privateKey,
                    certificate.getBytes(StandardCharsets.UTF_8), passphrase.getBytes());
        }
        jsch.addIdentity(appKey.getId().toString(), privateKey,
                appKey.getPublicKey().getBytes(), passphrase.getBytes());

        return certificate != null ? null : HostSystem.AUTH_METHOD_KEY;
    }

    /**
     * Captures the authentication method a session actually completed, by listening to JSch's
     * own log.
     * <p>
     * JSch exposes no accessor for this, and it is not something Bastillion can infer: the
     * method it offers first is not necessarily the one the host accepts, because
     * PreferredAuthentications also offers keyboard-interactive and password behind
     * publickey. Recording what was offered made the systems screen's Auth column misleading
     * in the one situation an operator consults it - a certificate rollout, where the
     * question is precisely whether the host took the certificate or quietly fell back.
     * <p>
     * JSch logs {@code "Authentication succeeded (<method>)."} at info once the method
     * completes, so that line is the answer. It also logs {@code "<algorithm> auth success"}
     * at debug, which is what distinguishes the certificate from the key it attests to when
     * both are offered as publickey identities - the method name is "publickey" either way.
     * Everything else is passed through to whatever logger was already in place, so attaching
     * this costs no logging; it does mean JSch builds its debug messages for these sessions,
     * which is a handful of strings per connection.
     */
    static final class AcceptedAuthMethodLogger implements com.jcraft.jsch.Logger {

        private static final String METHOD_PREFIX = "Authentication succeeded (";
        private static final String METHOD_SUFFIX = ").";
        private static final String ALGORITHM_SUFFIX = " auth success";

        private final com.jcraft.jsch.Logger delegate;
        private volatile String acceptedMethod;
        private volatile String acceptedAlgorithm;

        AcceptedAuthMethodLogger(com.jcraft.jsch.Logger delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean isEnabled(int level) {
            // Info and debug have to read as enabled whatever the delegate thinks, or JSch
            // skips building the two messages this class exists to read.
            return level == INFO || level == DEBUG || (delegate != null && delegate.isEnabled(level));
        }

        @Override
        public void log(int level, String message) {
            capture(level, message);
            if (delegate != null && delegate.isEnabled(level)) {
                delegate.log(level, message);
            }
        }

        @Override
        public void log(int level, String message, Throwable cause) {
            capture(level, message);
            if (delegate != null && delegate.isEnabled(level)) {
                delegate.log(level, message, cause);
            }
        }

        private void capture(int level, String message) {
            if (message == null) {
                return;
            }
            if (level == INFO && message.startsWith(METHOD_PREFIX) && message.endsWith(METHOD_SUFFIX)) {
                acceptedMethod = message.substring(METHOD_PREFIX.length(), message.length() - METHOD_SUFFIX.length());
            } else if (level == DEBUG && message.endsWith(ALGORITHM_SUFFIX)) {
                acceptedAlgorithm = message.substring(0, message.length() - ALGORITHM_SUFFIX.length()).trim();
            }
        }

        /** The method JSch completed, or null if it never logged one. */
        String acceptedMethod() {
            return acceptedMethod;
        }

        /** The public key algorithm JSch signed with, or null if it never logged one. */
        String acceptedAlgorithm() {
            return acceptedAlgorithm;
        }
    }

    /**
     * Marks out the OpenSSH certificate algorithm names, which are the plain key algorithm
     * with this infix - {@code ssh-ed25519-cert-v01@openssh.com} against
     * {@code ssh-ed25519}. Matching the infix rather than listing the algorithms keeps this
     * right for key types Bastillion does not sign certificates for today.
     */
    private static final String CERTIFICATE_ALGORITHM_INFIX = "-cert-v";

    /**
     * Resolves what to record in a system's Auth column from what JSch reports the host
     * accepted.
     * <p>
     * A publickey success is attributed by the algorithm that signed it, because the
     * certificate and the key it attests to are both offered as publickey identities and the
     * method name is "publickey" for either. Only when a single credential was offered, and
     * the algorithm went unreported, does {@code singleCredential} stand in for it.
     * <p>
     * A host that rejected the certificate and took a password must not be recorded as having
     * taken the certificate, so the fallback methods are their own state. An unrecognized or
     * missing method is left null rather than guessed at, which the systems screen renders as
     * unknown.
     */
    static String authMethodFor(String singleCredential, String acceptedMethod, String acceptedAlgorithm) {
        if (acceptedMethod == null) {
            return null;
        }
        return switch (acceptedMethod) {
            case "publickey" -> {
                if (acceptedAlgorithm != null) {
                    yield acceptedAlgorithm.contains(CERTIFICATE_ALGORITHM_INFIX)
                            ? HostSystem.AUTH_METHOD_CERTIFICATE
                            : HostSystem.AUTH_METHOD_KEY;
                }
                yield singleCredential;
            }
            case "password", "keyboard-interactive" -> HostSystem.AUTH_METHOD_PASSWORD;
            default -> null;
        };
    }

    /**
     * Records how a connection that has just succeeded authenticated, for the systems screen.
     * <p>
     * Best effort: the session is already up, so failing to note how it got there must not
     * fail the connection. A system being registered for the first time has no id yet and is
     * recorded on its next connection instead.
     */
    private static void recordAuthMethod(HostSystem hostSystem, String authMethod) {
        hostSystem.setLastAuthMethod(authMethod);
        try {
            SystemDB.updateAuthMethod(hostSystem.getId(), authMethod);
        } catch (Exception ex) {
            log.error("Could not record the authentication method for system {}", hostSystem.getId(), ex);
        }
    }

    /**
     * The Bastillion username behind a connection, for the certificate key id that the target
     * host logs. Best effort: a connection still proceeds if the lookup fails, just without
     * naming the user on the host side.
     */
    private static String usernameFor(Long userId) {
        if (userId == null) {
            return null;
        }
        try {
            User user = UserDB.getUser(userId);
            return user == null ? null : user.getUsername();
        } catch (Exception ex) {
            log.error("Could not read the username for user id {}", userId, ex);
            return null;
        }
    }

    /**
     * True if this failure was the host key being refused rather than anything else.
     * <p>
     * JSch raises a {@link JSchHostKeyException} subclass for an unknown, changed or revoked
     * host key, and for a host certificate signed by an untrusted CA - so the type tells us
     * this without matching on message text. The cause chain is walked because the connect
     * call wraps it.
     */
    private static final int MAX_CAUSE_DEPTH = 32;

    private static boolean isHostKeyRejection(Throwable ex) {
        // Bounded rather than guarded against self-reference: the JVM rejects an exception
        // that causes itself, but a two-element cycle (a caused by b, b later given a as its
        // cause) is constructible and would spin a naive walk forever. No real chain is
        // anywhere near this deep.
        Throwable t = ex;
        for (int depth = 0; t != null && depth < MAX_CAUSE_DEPTH; depth++, t = t.getCause()) {
            if (t instanceof JSchHostKeyException) {
                return true;
            }
        }
        return false;
    }

    /**
     * Records a failure as the status the screens act on: a refused host key points at the
     * Host Keys screen, and the two authentication failures are what make the terminal and
     * systems screens prompt for a password (AUTHFAIL) or a key passphrase (KEYAUTHFAIL)
     * and try again.
     * <p>
     * Shared by every connection path. Opening a terminal had its own copy that only knew
     * about host keys, so from 4.0.0 a host that wanted a password reported a bare "Failed"
     * and the password prompt that createTerms is built around never appeared.
     */
    private static void recordFailure(HostSystem hostSystem, Exception ex) {
        if (isHostKeyRejection(ex)) {
            hostSystem.setErrorMsg("The host key presented by this system was refused. "
                    + "Review it under Manage \u2192 Host Keys.");
            hostSystem.setStatusCd(HostSystem.HOST_KEY_FAIL_STATUS);
            return;
        }
        hostSystem.setErrorMsg(ex.getMessage());
        // Null for a SocketTimeoutException, an InterruptedException, or any NPE raised
        // without one - and this runs in the handler, so throwing here escapes the caller
        // entirely and turns a reportable failure into an HTTP 500.
        String msg = StringUtils.trimToEmpty(ex.getMessage()).toLowerCase();
        // JSch 2.x refuses a missing or wrong key passphrase in addIdentity, before
        // connecting, rather than with the USERAUTH fail it raises for a key still
        // encrypted at authentication time - both mean "ask for the passphrase".
        if (msg.contains("userauth fail") || msg.contains("incorrect passphrase")) {
            hostSystem.setStatusCd(HostSystem.PUBLIC_KEY_FAIL_STATUS);
        } else if (msg.contains("auth fail") || msg.contains("auth cancel")) {
            hostSystem.setStatusCd(HostSystem.AUTH_FAIL_STATUS);
        } else if (msg.contains("unknownhostexception")) {
            hostSystem.setErrorMsg("DNS Lookup Failed");
            hostSystem.setStatusCd(HostSystem.HOST_FAIL_STATUS);
        } else {
            hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
        }
    }

    // --- Authentication and Add Key ---
    public static HostSystem authAndAddPubKey(HostSystem hostSystem, String passphrase, String password) {
        JSch jsch = new JSch();
        Session session = null;
        hostSystem.setStatusCd(HostSystem.SUCCESS_STATUS);
        try {
            ApplicationKey appKey = PrivateKeyDB.getApplicationKey();
            if (StringUtils.isBlank(passphrase)) passphrase = appKey.getPassphrase();
            if (passphrase == null) passphrase = "";

            String singleCredential = addApplicationIdentity(jsch, appKey, passphrase, hostSystem, null);

            session = jsch.getSession(hostSystem.getUser(), hostSystem.getHost(), hostSystem.getPort());
            if (password != null && !password.isEmpty()) session.setPassword(password.getBytes(StandardCharsets.UTF_8));
            applyHostKeyVerification(jsch, session);
            session.setConfig("PreferredAuthentications", "publickey,keyboard-interactive,password");
            session.setServerAliveInterval(SERVER_ALIVE_INTERVAL);
            AcceptedAuthMethodLogger authMethodLogger = new AcceptedAuthMethodLogger(session.getLogger());
            session.setLogger(authMethodLogger);
            session.connect(SESSION_TIMEOUT);
            recordAuthMethod(hostSystem, authMethodFor(singleCredential,
                    authMethodLogger.acceptedMethod(), authMethodLogger.acceptedAlgorithm()));

            AuthorizedKeysUtil.addPubKey(hostSystem, session, appKey.getPublicKey());

        } catch (Exception ex) {
            log.info(ex.toString(), ex);
            recordFailure(hostSystem, ex);
        }
        if (session != null) session.disconnect();
        return hostSystem;
    }

    /**
     * Outcome of a certificate authentication test.
     *
     * @param ok      whether the host accepted a Bastillion-signed certificate
     * @param message what to tell the operator, in terms of what to do next
     */
    public record CertificateTestResult(boolean ok, String message) {
    }

    /**
     * Tries to authenticate to one system with a Bastillion-signed certificate and reports
     * what happened, without changing that system's recorded status.
     * <p>
     * Exists because {@code sshCertificateAuth} is a single global switch: without this, the
     * way to discover that a host was never given {@code TrustedUserCAKeys} is to turn
     * certificates on everywhere and watch connections fail. This answers the question for one
     * host first.
     * <p>
     * Deliberately issues a certificate regardless of whether the feature is switched on -
     * testing before enabling is the entire point - and deliberately offers <em>only</em>
     * publickey authentication. With keyboard-interactive or password left available, a host
     * that rejected the certificate could still complete the connection by another route and
     * the test would report success for a host that is not ready.
     * <p>
     * Does not touch authorized_keys and does not write the system's status. It is a real
     * connection, so host key verification applies as usual: under accept-new an unseen host
     * key is recorded by it, exactly as the first real connection would have.
     */
    public static CertificateTestResult testCertificateAuth(HostSystem hostSystem, String username) {
        JSch jsch = new JSch();
        Session session = null;
        try {
            ApplicationKey appKey = PrivateKeyDB.getApplicationKey();
            if (appKey == null) {
                return new CertificateTestResult(false, "No application SSH key has been generated yet.");
            }
            String unsupported = SshCertificateAuth.unsupportedKeyTypeReason(appKey.getPublicKey());
            if (unsupported != null) {
                return new CertificateTestResult(false, unsupported);
            }
            String certificate = SshCertificateAuth.issueCertificate(hostSystem, username);
            if (certificate == null) {
                return new CertificateTestResult(false,
                        "Could not issue a certificate. Check that a certificate authority exists "
                                + "and that this system has a login account set.");
            }

            String passphrase = appKey.getPassphrase() == null ? "" : appKey.getPassphrase();
            jsch.addIdentity(appKey.getId().toString(),
                    appKey.getPrivateKey().trim().getBytes(),
                    certificate.getBytes(StandardCharsets.UTF_8),
                    passphrase.getBytes());

            session = jsch.getSession(hostSystem.getUser(), hostSystem.getHost(), hostSystem.getPort());
            applyHostKeyVerification(jsch, session);
            session.setConfig("PreferredAuthentications", "publickey");
            session.connect(SESSION_TIMEOUT);

            return new CertificateTestResult(true,
                    hostSystem.getUser() + "@" + hostSystem.getHost() + ":" + hostSystem.getPort()
                            + " accepted a Bastillion-signed certificate. This system is ready for "
                            + "sshCertificateAuth=on.");

        } catch (Exception ex) {
            log.info("Certificate test failed for {}:{}", hostSystem.getHost(), hostSystem.getPort(), ex);
            return new CertificateTestResult(false, explainCertificateTestFailure(ex));
        } finally {
            if (session != null) {
                session.disconnect();
            }
        }
    }

    /**
     * Turns a failed certificate test into something an operator can act on. The common case
     * by far is the host never having been told to trust the authority.
     */
    private static String explainCertificateTestFailure(Exception ex) {
        if (isHostKeyRejection(ex)) {
            return "The host key was refused, so the certificate was never tried. "
                    + "Resolve it under Manage \u2192 Host Keys and test again.";
        }
        String message = ex.getMessage() == null ? "" : ex.getMessage().toLowerCase();
        if (message.contains("auth fail") || message.contains("auth cancel")) {
            return "The host refused the certificate. Check that its sshd_config has "
                    + "TrustedUserCAKeys pointing at this Bastillion's certificate authority key "
                    + "(Settings shows it), and that sshd has been reloaded since.";
        }
        if (message.contains("unknownhost")) {
            return "DNS lookup failed for this host.";
        }
        return "Could not connect: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
    }

    /**
     * Confirms a pasted private/public key pair (and passphrase, if the key is encrypted)
     * actually loads via JSch before it's ever written to application_key - an unvalidated
     * bad paste there would break every future SSH connection until fixed. Throws with a
     * message safe to show the user on any problem; returns normally if the pair is valid.
     */
    public static void validateKeyPair(String privateKey, String publicKey, String passphrase) throws JSchException {
        if (StringUtils.isEmpty(privateKey) || StringUtils.isEmpty(publicKey)) {
            throw new JSchException("Both the private and public key are required");
        }
        KeyPair keyPair;
        try {
            keyPair = KeyPair.load(new JSch(), privateKey.getBytes(StandardCharsets.UTF_8),
                    publicKey.getBytes(StandardCharsets.UTF_8));
        } catch (JSchException ex) {
            throw new JSchException("Could not parse the private/public key: " + ex.getMessage());
        }
        try {
            if (keyPair.isEncrypted() && !keyPair.decrypt(passphrase == null ? "" : passphrase)) {
                throw new JSchException("Passphrase is incorrect for this private key");
            }
        } finally {
            keyPair.dispose();
        }
    }

    // --- Distribution methods ---

    public static void distributePubKeysToAllSystems() throws SQLException, GeneralSecurityException {
        if (keyManagementEnabled) {
            for (HostSystem s : SystemDB.getAllSystems()) {
                s = SSHUtil.authAndAddPubKey(s, null, null);
                SystemDB.updateSystem(s);
            }
        }
    }

    public static void distributePubKeysToProfile(Long profileId) throws SQLException, GeneralSecurityException {
        if (keyManagementEnabled) {
            for (HostSystem s : ProfileSystemsDB.getSystemsByProfile(profileId)) {
                s = SSHUtil.authAndAddPubKey(s, null, null);
                SystemDB.updateSystem(s);
            }
        }
    }
}
