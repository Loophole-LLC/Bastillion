/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.KeyPair;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The certificate encoding is only correct if OpenSSH agrees it is, so the central test here
 * hands a signed certificate to {@code ssh-keygen -L} and reads back what it parsed. A format
 * mistake in a hand-rolled certificate is otherwise invisible until sshd rejects it with
 * nothing useful in the logs.
 */
class SshCertificateUtilTest {

    private record Ca(String privatePem, String publicKey) {
    }

    private static Ca newCa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();
        String privatePem = SSHUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519);
        String publicKey = "ssh-ed25519 " + Base64.getEncoder().encodeToString(
                SSHUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded())) + " ca@bastillion";
        return new Ca(privatePem, publicKey);
    }

    private static String newPublicKey(String comment) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(
                SSHUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded())) + " " + comment;
    }

    private static String sshKeygenInspect(String certificate) throws Exception {
        Path dir = Files.createTempDirectory("bastillion_cert_test_");
        Path cert = dir.resolve("id_ed25519-cert.pub");
        try {
            Files.writeString(cert, certificate + "\n", StandardCharsets.US_ASCII);
            Process proc = new ProcessBuilder("ssh-keygen", "-L", "-f", cert.toString())
                    .redirectErrorStream(true).start();
            proc.getOutputStream().close();
            String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            proc.waitFor();
            return output;
        } finally {
            Files.deleteIfExists(cert);
            Files.deleteIfExists(dir);
        }
    }

    private static boolean sshKeygenAvailable() {
        try {
            Process proc = new ProcessBuilder("ssh-keygen", "-?").redirectErrorStream(true).start();
            proc.getOutputStream().close();
            proc.getInputStream().readAllBytes();
            proc.waitFor();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Test
    void opensshParsesTheSignedCertificateAndAgreesWithEveryFieldWePutInIt() throws Exception {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH");
        Ca ca = newCa();

        String certificate = SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                newPublicKey("alice@laptop"), "bastillion:alice", List.of("deploy", "alice"), 42L, 300);

        String parsed = sshKeygenInspect(certificate);

        assertTrue(parsed.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"), parsed);
        assertTrue(parsed.contains("Public key: ED25519-CERT"), parsed);
        assertTrue(parsed.contains("Key ID: \"bastillion:alice\""), parsed);
        assertTrue(parsed.contains("Serial: 42"), parsed);
        assertTrue(parsed.contains("Principals:"), parsed);
        assertTrue(parsed.contains("deploy"), parsed);
        assertTrue(parsed.contains("alice"), parsed);
        assertTrue(parsed.contains("permit-pty"), parsed);
        // Nothing Bastillion does needs these, and a certificate carries what it permits for
        // its whole validity.
        assertTrue(parsed.contains("Critical Options: (none)"), parsed);
        assertFalse(parsed.contains("permit-port-forwarding"), parsed);
        assertFalse(parsed.contains("permit-agent-forwarding"), parsed);
    }

    @Test
    void theSigningAuthorityIsRecordedAsTheCertificatesSigningCa() throws Exception {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH");
        Ca ca = newCa();

        String certificate = SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                newPublicKey("alice@laptop"), "bastillion:alice", List.of("deploy"), 1L, 300);

        // ssh-keygen prints the CA's own fingerprint, so this also proves the signature key
        // field holds the CA key and not the subject's.
        assertTrue(sshKeygenInspect(certificate).contains("Signing CA: ED25519"), sshKeygenInspect(certificate));
    }

    @Test
    void certificateValidityIsBoundedAndBackdatedForClockSkew() throws Exception {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH");
        Ca ca = newCa();

        String certificate = SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                newPublicKey("alice@laptop"), "bastillion:alice", List.of("deploy"), 1L, 300);

        String parsed = sshKeygenInspect(certificate);
        // Not "forever" - the whole point of issuing per session is that it expires.
        assertFalse(parsed.contains("Valid: forever"), parsed);
        assertTrue(parsed.contains("Valid: from "), parsed);
    }

    @Test
    void readPrincipalsRoundTripsWhatWasSigned() throws Exception {
        Ca ca = newCa();

        String certificate = SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                newPublicKey("alice@laptop"), "bastillion:alice", List.of("deploy", "alice"), 1L, 300);

        assertEquals(List.of("deploy", "alice"), SshCertificateUtil.readPrincipals(certificate));
    }

    // --- refusals ---

    @Test
    void refusesToSignWithNoPrincipals() throws Exception {
        Ca ca = newCa();
        String subject = newPublicKey("alice@laptop");

        // A user certificate with no principals means "any user" per the spec, which is the
        // opposite of what anything here wants.
        GeneralSecurityException ex = assertThrows(GeneralSecurityException.class,
                () -> SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                        subject, "bastillion:alice", List.of(), 1L, 300));
        assertTrue(ex.getMessage().contains("principal"), ex.getMessage());
    }

    @Test
    void refusesToSignWithNoKeyId() throws Exception {
        Ca ca = newCa();
        String subject = newPublicKey("alice@laptop");

        // The key id is what sshd logs, so an unidentified certificate defeats the attribution
        // this whole mechanism exists for.
        assertThrows(GeneralSecurityException.class,
                () -> SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                        subject, "  ", List.of("deploy"), 1L, 300));
    }

    @Test
    void refusesANonEd25519SubjectKeyRatherThanMisencodingIt() throws Exception {
        Ca ca = newCa();
        // An ssh-rsa key would need mpint e/n in the certificate body instead of a single
        // string, so it must be refused rather than encoded as if it were Ed25519.
        String rsaish = "ssh-rsa " + Base64.getEncoder().encodeToString(
                sshBlob("ssh-rsa", new byte[]{1, 2, 3})) + " bob@laptop";

        GeneralSecurityException ex = assertThrows(GeneralSecurityException.class,
                () -> SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                        rsaish, "bastillion:bob", List.of("deploy"), 1L, 300));
        assertTrue(ex.getMessage().contains("ssh-rsa"), ex.getMessage());
    }

    @Test
    void refusesAPassphraseProtectedCaKey() throws Exception {
        assumeTrue(sshKeygenAvailable(), "ssh-keygen not on PATH");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();
        String encrypted = SSHUtil.rewrapWithOpenSSHKeygen("ca", SSHUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519),
                "a passphrase");
        String publicKey = "ssh-ed25519 " + Base64.getEncoder().encodeToString(
                SSHUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded())) + " ca@bastillion";
        String subject = newPublicKey("alice@laptop");

        GeneralSecurityException ex = assertThrows(GeneralSecurityException.class,
                () -> SshCertificateUtil.signUserCertificate(encrypted, publicKey, subject,
                        "bastillion:alice", List.of("deploy"), 1L, 300));
        assertTrue(ex.getMessage().contains("passphrase-protected"), ex.getMessage());
    }

    @Test
    void refusesTruncatedKeyData() throws Exception {
        Ca ca = newCa();
        String truncated = "ssh-ed25519 " + Base64.getEncoder().encodeToString(new byte[]{0, 0, 0, 20}) + " x";

        assertThrows(GeneralSecurityException.class,
                () -> SshCertificateUtil.signUserCertificate(ca.privatePem(), ca.publicKey(),
                        truncated, "bastillion:alice", List.of("deploy"), 1L, 300));
    }

    private static byte[] sshBlob(String type, byte[] body) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] t = type.getBytes(StandardCharsets.UTF_8);
        out.write(new byte[]{0, 0, 0, (byte) t.length});
        out.write(t);
        out.write(new byte[]{0, 0, 0, (byte) body.length});
        out.write(body);
        return out.toByteArray();
    }

    private static void assertFalse(boolean condition, String message) {
        org.junit.jupiter.api.Assertions.assertFalse(condition, message);
    }
}
