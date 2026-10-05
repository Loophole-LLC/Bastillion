/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import io.bastillion.manage.db.HostKeyDB;
import io.bastillion.manage.model.KnownHostKey;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;

/**
 * Covers the host key verification decisions in {@link HostKeyVerifier#check}, which is what
 * replaced opening every SSH session with {@code StrictHostKeyChecking=no}.
 */
class HostKeyVerifierTest {

    private static final JSch JSCH = new JSch();

    /**
     * A real ssh-ed25519 host key blob: the SSH wire encoding of the string "ssh-ed25519"
     * followed by a 32-byte key, which is what a server sends and what JSch hands to
     * HostKeyRepository.check(). Built rather than hard-coded so the type JSch parses out of
     * it is genuinely derived from the bytes.
     */
    private static byte[] ed25519Blob(byte fill) {
        byte[] type = "ssh-ed25519".getBytes();
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, fill);
        byte[] blob = new byte[4 + type.length + 4 + key.length];
        int i = 0;
        i = writeLength(blob, i, type.length);
        System.arraycopy(type, 0, blob, i, type.length);
        i += type.length;
        i = writeLength(blob, i, key.length);
        System.arraycopy(key, 0, blob, i, key.length);
        return blob;
    }

    private static int writeLength(byte[] target, int offset, int length) {
        target[offset] = (byte) (length >>> 24);
        target[offset + 1] = (byte) (length >>> 16);
        target[offset + 2] = (byte) (length >>> 8);
        target[offset + 3] = (byte) length;
        return offset + 4;
    }

    private static String base64(byte[] blob) {
        return java.util.Base64.getEncoder().encodeToString(blob);
    }

    private static KnownHostKey trusted(String publicKey) {
        KnownHostKey known = new KnownHostKey();
        known.setHost("web01");
        known.setPort(22);
        known.setType("ssh-ed25519");
        known.setPublicKey(publicKey);
        known.setFingerprint("SHA256:recorded");
        known.setStatus(KnownHostKey.TRUSTED);
        return known;
    }

    @Test
    void acceptsAHostPresentingItsRecordedKey() throws Exception {
        byte[] blob = ed25519Blob((byte) 1);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey("web01", 22, "ssh-ed25519"))
                    .thenReturn(trusted(base64(blob)));

            assertEquals(HostKeyRepository.OK, new HostKeyVerifier(JSCH).check("web01", blob));
        }
    }

    @Test
    void refusesAndRecordsAHostWhoseKeyChanged() throws Exception {
        byte[] recorded = ed25519Blob((byte) 1);
        byte[] offered = ed25519Blob((byte) 2);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey("web01", 22, "ssh-ed25519"))
                    .thenReturn(trusted(base64(recorded)));

            assertEquals(HostKeyRepository.CHANGED, new HostKeyVerifier(JSCH).check("web01", offered));

            // the offered key is recorded alongside the trusted one, not over it
            db.verify(() -> HostKeyDB.markChanged(eq("web01"), eq(22), eq("ssh-ed25519"),
                    eq(base64(offered)), anyString()));
        }
    }

    @Test
    void refusesARevokedHostKey() throws Exception {
        byte[] blob = ed25519Blob((byte) 1);
        KnownHostKey revoked = trusted(base64(blob));
        revoked.setStatus(KnownHostKey.REVOKED);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey("web01", 22, "ssh-ed25519")).thenReturn(revoked);

            assertEquals(HostKeyRepository.NOT_INCLUDED, new HostKeyVerifier(JSCH).check("web01", blob));
        }
    }

    @Test
    void refusesAHostKeyStillAwaitingApproval() throws Exception {
        byte[] blob = ed25519Blob((byte) 1);
        KnownHostKey pending = trusted(base64(blob));
        pending.setStatus(KnownHostKey.PENDING);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey("web01", 22, "ssh-ed25519")).thenReturn(pending);

            assertEquals(HostKeyRepository.NOT_INCLUDED, new HostKeyVerifier(JSCH).check("web01", blob));
        }
    }

    @Test
    void recordsAndTrustsAHostSeenForTheFirstTimeUnderAcceptNew() throws Exception {
        // The default mode; isStrict() is false unless hostKeyVerification=strict is set.
        byte[] blob = ed25519Blob((byte) 3);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey(anyString(), anyInt(), anyString())).thenReturn(null);

            int result = new HostKeyVerifier(JSCH).check("web01", blob);

            assertEquals(HostKeyRepository.OK, result);
            db.verify(() -> HostKeyDB.insertHostKey(eq("web01"), eq(22), eq("ssh-ed25519"),
                    eq(base64(blob)), anyString(), eq(KnownHostKey.TRUSTED)));
        }
    }

    @Test
    void failsClosedWhenTheKeyStoreCannotBeRead() throws Exception {
        // An unreadable store is not a reason to accept an unverified key on a bastion.
        byte[] blob = ed25519Blob((byte) 1);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey(anyString(), anyInt(), anyString()))
                    .thenThrow(new java.sql.SQLException("database is locked"));

            assertEquals(HostKeyRepository.NOT_INCLUDED, new HostKeyVerifier(JSCH).check("web01", blob));
        }
    }

    @Test
    void refusesAKeyBlobItCannotParse() {
        assertEquals(HostKeyRepository.NOT_INCLUDED,
                new HostKeyVerifier(JSCH).check("web01", new byte[]{0, 0}));
    }

    @Test
    void ignoresJschsOwnRequestToAddAKey() throws Exception {
        // JSch must not be able to write a key into the store itself - check() is where the
        // verification mode is applied.
        byte[] blob = ed25519Blob((byte) 1);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            new HostKeyVerifier(JSCH).add(new com.jcraft.jsch.HostKey("web01", blob), null);

            db.verifyNoInteractions();
        }
    }

    // --- host:port parsing, as JSch formats it for a non-default port ---

    @Test
    void parsesABracketedHostAndPort() {
        HostKeyVerifier.HostAddress address = HostKeyVerifier.HostAddress.parse("[db01.example.com]:2222");
        assertEquals("db01.example.com", address.host());
        assertEquals(2222, address.port());
    }

    @Test
    void parsesABareHostAsTheDefaultSshPort() {
        HostKeyVerifier.HostAddress address = HostKeyVerifier.HostAddress.parse("db01.example.com");
        assertEquals("db01.example.com", address.host());
        assertEquals(22, address.port());
    }

    @Test
    void checksTheBracketedPortSeparatelyFromTheSameHostOnAnotherPort() throws Exception {
        byte[] blob = ed25519Blob((byte) 1);
        try (MockedStatic<HostKeyDB> db = mockStatic(HostKeyDB.class)) {
            db.when(() -> HostKeyDB.getHostKey("web01", 2222, "ssh-ed25519"))
                    .thenReturn(trusted(base64(blob)));
            db.when(() -> HostKeyDB.getHostKey("web01", 22, "ssh-ed25519")).thenReturn(null);

            assertEquals(HostKeyRepository.OK,
                    new HostKeyVerifier(JSCH).check("[web01]:2222", blob));
        }
    }

    @Test
    void verificationIsOnByDefault() {
        assertTrue(HostKeyVerifier.isEnabled());
    }
}
