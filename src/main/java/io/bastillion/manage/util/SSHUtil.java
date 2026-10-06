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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

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

    // --- authorized_keys Content Guards ---

    // addPubKey reads and writes authorized_keys over SFTP, so neither of these values is
    // ever handed to a remote shell and neither guard is load-bearing against command
    // injection any more (see addPubKey). They are kept as input validation: a plain
    // relative/absolute path, and key lines that cannot corrupt the file they are written
    // into. Rejecting shell metacharacters is now purely defense-in-depth, in case a value
    // ever reaches an unquoted shell context again.
    private static final Pattern SAFE_AUTHORIZED_KEYS_PATH = Pattern.compile("[A-Za-z0-9_./-]+");

    // A CR or LF inside a single key line would split it into two authorized_keys entries,
    // letting a crafted key comment append an entry of its own (with its own options, e.g.
    // command= or from=). The shell metacharacters are rejected as defense-in-depth.
    private static final Pattern UNSAFE_KEY_CHARS = Pattern.compile("['\"`$;|&\\r]");

    // package-private (rather than private) so SSHUtilTest can exercise the guards directly
    static boolean isSafeAuthorizedKeysPath(String path) {
        return StringUtils.isNotBlank(path) && SAFE_AUTHORIZED_KEYS_PATH.matcher(path).matches();
    }

    static boolean isSafeKeyContent(String key) {
        return StringUtils.isNotBlank(key) && !UNSAFE_KEY_CHARS.matcher(key).find();
    }

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

                String opensshPEM = buildOpenSSHPrivateKey(newPair, type);
                Files.writeString(tmpPvt, opensshPEM, StandardCharsets.US_ASCII);

                String publicKeyContent = generateOpenSSHPublicKey(newPair, comment, type);
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

    // --- Legacy-compatible methods restored ---

    public static byte[] encodeSSHPublicKey(String keyType, byte[] rawPubBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeSSHString(out, keyType.getBytes(StandardCharsets.UTF_8));
        byte[] keyPart = extractRawKeyFromX509(rawPubBytes);
        writeSSHBytes(out, keyPart);
        return out.toByteArray();
    }

    public static String buildOpenSSHPrivateKey(Long userId, java.security.KeyPair kp, int type, String passphrase)
            throws IOException, GeneralSecurityException, InterruptedException {
        String unencryptedPEM = buildOpenSSHPrivateKey(kp, type);
        if (StringUtils.isBlank(passphrase)) return unencryptedPEM;
        return rewrapWithOpenSSHKeygen(userId != null ? userId.toString() : UUID.randomUUID().toString(),
                unencryptedPEM, passphrase);
    }

    // ---- SSH key distribution methods ----

    public static HostSystem addPubKey(HostSystem hostSystem, Session session, String appPublicKey) {
        if (!KeyManagement.writesAuthorizedKeys()) {
            // keyManagement=off: the host's authorized_keys is not ours to touch. Reaching
            // here at all means authentication already succeeded by some other means, which
            // in practice is an SSH certificate - so there is nothing to add and nothing to
            // reconcile. Status is left as the caller set it.
            return hostSystem;
        }
        try {
            String authorizedKeys = hostSystem.getAuthorizedKeys().replaceAll("~\\/|~", "");
            if (!isSafeAuthorizedKeysPath(authorizedKeys)) {
                log.error("Refusing to push keys for system {}: authorized_keys path '{}' contains disallowed characters",
                        hostSystem.getId(), authorizedKeys);
                hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
                return hostSystem;
            }

            String existingKeys = readAuthorizedKeys(session, authorizedKeys);
            String appPubKey = appPublicKey.replace("\n", "").trim();
            if (!isSafeKeyContent(appPubKey)) {
                log.error("Refusing to push keys for system {}: application public key contains disallowed characters",
                        hostSystem.getId());
                hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
                return hostSystem;
            }

            String newKeys;
            if (keyManagementEnabled) {
                List<String> assigned = PublicKeyDB.getPublicKeysForSystem(hostSystem.getId());
                StringBuilder sb = new StringBuilder();
                for (String k : assigned) {
                    String key = k.replace("\n", "").trim();
                    if (!isSafeKeyContent(key)) {
                        log.error("Skipping public key for system {}: key contains disallowed characters", hostSystem.getId());
                        continue;
                    }
                    sb.append(key).append("\n");
                }
                sb.append(appPubKey);
                newKeys = sb.toString();
            } else {
                // Key management off: leave whatever is already on the host alone and just
                // make sure Bastillion's own key is present. existingKeys is host-controlled
                // content that is written straight back out, which is safe only because
                // writeAuthorizedKeys uses SFTP rather than a shell command.
                if (!existingKeys.contains(appPubKey))
                    newKeys = existingKeys + "\n" + appPubKey;
                else newKeys = existingKeys;
            }

            if (!newKeys.equals(existingKeys)) {
                writeAuthorizedKeys(session, authorizedKeys, newKeys);
            }
        } catch (Exception ex) {
            log.error(ex.toString(), ex);
        }
        return hostSystem;
    }

    /**
     * Reads the remote authorized_keys file over SFTP, returning "" if it does not exist yet.
     * <p>
     * Deliberately not {@code cat <path>} over an exec channel: the contents come back here
     * and are written out again by {@link #writeAuthorizedKeys}, and routing them through a
     * shell command line meant any quote already present in the file (an apostrophe in a key
     * comment is perfectly legal) could terminate the quoting of the command that rewrote it.
     * SFTP transfers the bytes with no shell on either end, so the file's existing contents
     * need no escaping or validation at all.
     */
    private static String readAuthorizedKeys(Session session, String authorizedKeys) throws JSchException, SftpException, IOException {
        ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
        try {
            sftp.connect(CHANNEL_TIMEOUT);
            try (InputStream in = sftp.get(authorizedKeys)) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            } catch (SftpException ex) {
                if (ex.id == ChannelSftp.SSH_FX_NO_SUCH_FILE) {
                    return "";
                }
                throw ex;
            }
        } finally {
            sftp.disconnect();
        }
    }

    /**
     * Replaces the remote authorized_keys file over SFTP and sets it back to 0600.
     */
    private static void writeAuthorizedKeys(Session session, String authorizedKeys, String contents) throws JSchException, SftpException {
        ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
        try {
            sftp.connect(CHANNEL_TIMEOUT);
            sftp.put(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)), authorizedKeys);
            sftp.chmod(0600, authorizedKeys);
        } finally {
            sftp.disconnect();
        }
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

            String authMethod = addApplicationIdentity(jsch, appKey, passphrase, hostSystem, usernameFor(userId));

            Session session = jsch.getSession(hostSystem.getUser(), hostSystem.getHost(), hostSystem.getPort());
            if (StringUtils.isNotBlank(password)) session.setPassword(password.getBytes(StandardCharsets.UTF_8));
            applyHostKeyVerification(jsch, session);
            session.setConfig("PreferredAuthentications", "publickey,keyboard-interactive,password");
            session.setServerAliveInterval(SERVER_ALIVE_INTERVAL);
            session.connect(SESSION_TIMEOUT);

            recordAuthMethod(hostSystem, authMethod);

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

            addPubKey(hostSystem, session, appKey.getPublicKey());
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
     */
    private static String addApplicationIdentity(JSch jsch, ApplicationKey appKey, String passphrase,
                                                 HostSystem hostSystem, String username) throws JSchException {
        String certificate = SshCertificateAuth.certificateFor(hostSystem, username);
        byte[] publicCredential = certificate != null
                ? certificate.getBytes(StandardCharsets.UTF_8)
                : appKey.getPublicKey().getBytes();

        jsch.addIdentity(appKey.getId().toString(),
                appKey.getPrivateKey().trim().getBytes(),
                publicCredential,
                passphrase.getBytes());

        return certificate != null ? HostSystem.AUTH_METHOD_CERTIFICATE : HostSystem.AUTH_METHOD_KEY;
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
     * Records a failure, singling out a refused host key so the systems list can say what
     * actually happened and point at the screen that resolves it.
     */
    private static void recordFailure(HostSystem hostSystem, Exception ex) {
        if (isHostKeyRejection(ex)) {
            hostSystem.setErrorMsg("The host key presented by this system was refused. "
                    + "Review it under Manage \u2192 Host Keys.");
            hostSystem.setStatusCd(HostSystem.HOST_KEY_FAIL_STATUS);
            return;
        }
        hostSystem.setErrorMsg(ex.getMessage());
        hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
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

            String authMethod = addApplicationIdentity(jsch, appKey, passphrase, hostSystem, null);

            session = jsch.getSession(hostSystem.getUser(), hostSystem.getHost(), hostSystem.getPort());
            if (password != null && !password.isEmpty()) session.setPassword(password.getBytes(StandardCharsets.UTF_8));
            applyHostKeyVerification(jsch, session);
            session.setConfig("PreferredAuthentications", "publickey,keyboard-interactive,password");
            session.setServerAliveInterval(SERVER_ALIVE_INTERVAL);
            session.connect(SESSION_TIMEOUT);
            recordAuthMethod(hostSystem, authMethod);

            addPubKey(hostSystem, session, appKey.getPublicKey());

        } catch (Exception ex) {
            log.info(ex.toString(), ex);
            if (isHostKeyRejection(ex)) {
                recordFailure(hostSystem, ex);
                if (session != null) session.disconnect();
                return hostSystem;
            }
            hostSystem.setErrorMsg(ex.getMessage());
            String msg = ex.getMessage().toLowerCase();
            if (msg.contains("userauth fail")) hostSystem.setStatusCd(HostSystem.PUBLIC_KEY_FAIL_STATUS);
            else if (msg.contains("auth fail") || msg.contains("auth cancel"))
                hostSystem.setStatusCd(HostSystem.AUTH_FAIL_STATUS);
            else if (msg.contains("unknownhostexception")) {
                hostSystem.setErrorMsg("DNS Lookup Failed");
                hostSystem.setStatusCd(HostSystem.HOST_FAIL_STATUS);
            } else hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
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

    // --- Fingerprint helper ---
    public static String getFingerprint(String publicKey) {
        String fingerprint = null;
        if (StringUtils.isNotEmpty(publicKey)) {
            if (publicKey.contains("ssh-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ssh-"));
            } else if (publicKey.contains("ecdsa-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ecdsa-"));
            }
            try {
                KeyPair keyPair = KeyPair.load(new JSch(), null, publicKey.getBytes());
                if (keyPair != null) {
                    fingerprint = keyPair.getFingerPrint();
                }
            } catch (JSchException ex) {
                log.error(ex.toString(), ex);
            }
        }
        return fingerprint;
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
    /**
     * Returns public key type from an OpenSSH public key string.
     * Recognizes DSA, RSA, ECDSA, ED25519, ED448.
     */
    public static String getKeyType(String publicKey) {
        String keyType = null;
        if (StringUtils.isNotEmpty(publicKey)) {
            // Normalize to start at the algorithm token
            if (publicKey.contains("ssh-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ssh-"));
            } else if (publicKey.contains("ecdsa-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ecdsa-"));
            }
            try {
                KeyPair keyPair = KeyPair.load(new JSch(), null, publicKey.getBytes(StandardCharsets.UTF_8));
                if (keyPair != null) {
                    int type = keyPair.getKeyType();
                    if (KeyPair.DSA == type)        keyType = "DSA";
                    else if (KeyPair.RSA == type)    keyType = "RSA";
                    else if (KeyPair.ECDSA == type)  keyType = "ECDSA";
                    else if (KeyPair.ED25519 == type)keyType = "ED25519";
                    else if (KeyPair.ED448 == type)  keyType = "ED448";
                    else if (KeyPair.UNKNOWN == type)keyType = "UNKNOWN";
                    else if (KeyPair.ERROR == type)  keyType = "ERROR";
                }
            } catch (JSchException ex) {
                log.error(ex.toString(), ex);
            }
        }
        return keyType;
    }


    public static void distributePubKeysToProfile(Long profileId) throws SQLException, GeneralSecurityException {
        if (keyManagementEnabled) {
            for (HostSystem s : ProfileSystemsDB.getSystemsByProfile(profileId)) {
                s = SSHUtil.authAndAddPubKey(s, null, null);
                SystemDB.updateSystem(s);
            }
        }
    }

    // --- Encoding Helpers ---

    public static String buildOpenSSHPrivateKey(java.security.KeyPair kp, int type) throws IOException {
        String keyType = (type == KeyPair.ED25519) ? "ssh-ed25519" : "ssh-ed448";
        ByteArrayOutputStream outer = new ByteArrayOutputStream();
        outer.write("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII));
        writeSSHString(outer, "none".getBytes());
        writeSSHString(outer, "none".getBytes());
        writeSSHString(outer, new byte[0]);
        outer.write(ByteBuffer.allocate(4).putInt(1).array());

        ByteArrayOutputStream pubBlob = new ByteArrayOutputStream();
        writeSSHString(pubBlob, keyType.getBytes());
        byte[] pubRaw = extractRawKeyFromX509(kp.getPublic().getEncoded());
        writeSSHBytes(pubBlob, pubRaw);
        writeSSHBytes(outer, pubBlob.toByteArray());

        ByteArrayOutputStream privBlob = new ByteArrayOutputStream();
        int chk = new SecureRandom().nextInt();
        privBlob.write(ByteBuffer.allocate(4).putInt(chk).array());
        privBlob.write(ByteBuffer.allocate(4).putInt(chk).array());
        writeSSHString(privBlob, keyType.getBytes());
        writeSSHBytes(privBlob, pubRaw);

        byte[] privRaw = extractRawKeyFromX509(kp.getPrivate().getEncoded());
        if (keyType.equals("ssh-ed25519") && privRaw.length > 32)
            privRaw = Arrays.copyOfRange(privRaw, privRaw.length - 32, privRaw.length);
        ByteArrayOutputStream combo = new ByteArrayOutputStream();
        combo.write(privRaw);
        combo.write(pubRaw);
        writeSSHBytes(privBlob, combo.toByteArray());
        writeSSHString(privBlob, "".getBytes());
        int padLen = 8 - (privBlob.size() % 8);
        for (int i = 1; i <= padLen; i++) privBlob.write(i);
        writeSSHBytes(outer, privBlob.toByteArray());
        String base64 = Base64.getMimeEncoder(70, "\n".getBytes())
                .encodeToString(outer.toByteArray());
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64 +
                "\n-----END OPENSSH PRIVATE KEY-----\n";
    }

    private static String generateOpenSSHPublicKey(java.security.KeyPair kp, String comment, int type) throws IOException {
        String algo = (type == KeyPair.ED25519) ? "ssh-ed25519" :
                (type == KeyPair.ED448) ? "ssh-ed448" : "ssh-unknown";
        byte[] rawPub = extractRawKeyFromX509(kp.getPublic().getEncoded());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeSSHString(out, algo.getBytes());
        writeSSHBytes(out, rawPub);
        String encoded = Base64.getEncoder().encodeToString(out.toByteArray());
        return algo + " " + encoded + " " + comment + "\n";
    }

    public static void writeSSHString(ByteArrayOutputStream out, byte[] data) throws IOException {
        out.write(ByteBuffer.allocate(4).putInt(data.length).array());
        out.write(data);
    }

    public static void writeSSHBytes(ByteArrayOutputStream out, byte[] bytes) throws IOException {
        out.write(ByteBuffer.allocate(4).putInt(bytes.length).array());
        out.write(bytes);
    }

    public static byte[] extractRawKeyFromX509(byte[] x509Encoded) {
        for (int i = 0; i < x509Encoded.length - 3; i++) {
            if (x509Encoded[i] == 0x03 && x509Encoded[i + 2] == 0x00)
                return Arrays.copyOfRange(x509Encoded, i + 3, x509Encoded.length);
        }
        return x509Encoded;
    }

    /**
     * ssh-keygen here is local and non-interactive and finishes in milliseconds. A process
     * still alive after this has stopped to prompt for something, and will never be answered.
     */
    private static final long KEYGEN_TIMEOUT_SECONDS = 30;

    private static final byte[] OPENSSH_KEY_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final String CIPHER_NONE = "none";

    /**
     * Re-encrypts a freshly generated OpenSSH private key under the user's passphrase, by
     * handing it to ssh-keygen.
     * <p>
     * Every failure here has to be loud. This runs on the path that generates a key for a
     * user to download ({@code AuthKeysKtrl.generateUserKey}), so the caller cannot tell a
     * rewrapped key from the plaintext one it passed in by looking at it - and the user is
     * told the result is protected by the passphrase they just chose. The previous version
     * called {@code proc.waitFor()}, discarded the exit status and returned the file
     * regardless, so any ssh-keygen failure returned the key still completely unencrypted.
     */
    public static String rewrapWithOpenSSHKeygen(String userId, String pem, String passphrase)
            throws IOException, InterruptedException, GeneralSecurityException {
        Path tmp = Files.createTempFile("bastillion_key_" + userId + "_", ".key");
        Files.write(tmp, pem.getBytes(StandardCharsets.US_ASCII));
        try {
            try {
                Files.setPosixFilePermissions(tmp, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException ignored) {}
            ProcessBuilder pb = new ProcessBuilder("ssh-keygen", "-p", "-P", "",
                    "-N", passphrase, "-f", tmp.toString(), "-o", "-a", "16");
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            // Close the child's stdin straight away. It is a pipe this end never writes to,
            // so had ssh-keygen decided to prompt - a wrong -P, a format it would rather ask
            // about - it would have blocked on a read that nothing was ever going to satisfy.
            // At EOF it fails and exits instead, which is what makes draining its output
            // below safe to do on this thread.
            proc.getOutputStream().close();

            // Read the merged output before waiting, not after. redirectErrorStream was
            // already set but nothing ever read the pipe, so output large enough to fill the
            // buffer would have left ssh-keygen blocked writing and waitFor() blocked on
            // ssh-keygen.
            String output;
            try (InputStream out = proc.getInputStream()) {
                output = new String(out.readAllBytes(), StandardCharsets.UTF_8).trim();
            }

            if (!proc.waitFor(KEYGEN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
                throw new GeneralSecurityException("ssh-keygen did not finish within "
                        + KEYGEN_TIMEOUT_SECONDS + "s while applying a passphrase to the generated key");
            }
            if (proc.exitValue() != 0) {
                throw new GeneralSecurityException("ssh-keygen failed (exit " + proc.exitValue()
                        + ") while applying a passphrase to the generated key"
                        + (output.isEmpty() ? "" : ": " + output));
            }

            String rewrapped = Files.readString(tmp, StandardCharsets.US_ASCII);
            // Check the property the user is relying on, rather than trusting the exit status
            // to imply it. This is the last point at which an unencrypted key can be stopped.
            if (!isEncryptedOpenSSHPrivateKey(rewrapped)) {
                throw new GeneralSecurityException(
                        "ssh-keygen reported success but the generated private key is not encrypted");
            }
            return rewrapped;
        } finally {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) {}
        }
    }

    /**
     * True if this is an OpenSSH private key whose contents are encrypted.
     * <p>
     * The openssh-key-v1 container names its cipher in the clear: the magic is followed by an
     * SSH string holding the cipher name, which is literally "none" for an unencrypted key
     * (see {@link #buildOpenSSHPrivateKey(java.security.KeyPair, int)}, which writes exactly
     * that). Anything whose format cannot be read is reported as not encrypted - this backs a
     * security check, so being unable to prove encryption counts as failing it.
     */
    static boolean isEncryptedOpenSSHPrivateKey(String pem) {
        if (StringUtils.isBlank(pem)) {
            return false;
        }
        String body = StringUtils.substringBetween(pem,
                "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----");
        if (body == null) {
            return false;
        }
        byte[] decoded;
        try {
            decoded = Base64.getMimeDecoder().decode(body);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (decoded.length < OPENSSH_KEY_MAGIC.length + 4) {
            return false;
        }
        if (!Arrays.equals(Arrays.copyOf(decoded, OPENSSH_KEY_MAGIC.length), OPENSSH_KEY_MAGIC)) {
            return false;
        }
        ByteBuffer buffer = ByteBuffer.wrap(decoded, OPENSSH_KEY_MAGIC.length,
                decoded.length - OPENSSH_KEY_MAGIC.length);
        int cipherLength = buffer.getInt();
        if (cipherLength < 0 || cipherLength > buffer.remaining()) {
            return false;
        }
        byte[] cipher = new byte[cipherLength];
        buffer.get(cipher);
        return !CIPHER_NONE.equals(new String(cipher, StandardCharsets.US_ASCII));
    }
}
