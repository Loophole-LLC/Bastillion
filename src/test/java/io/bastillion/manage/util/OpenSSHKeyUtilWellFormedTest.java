/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenSSHKeyUtilWellFormedTest {

    private static String line(int type, int size, String algorithm) throws Exception {
        KeyPair kp = KeyPair.genKeyPair(new JSch(), type, size);
        return algorithm + " " + Base64.getEncoder().encodeToString(kp.getPublicKeyBlob()) + " someone@laptop";
    }

    private static String ed25519() throws Exception {
        return line(KeyPair.ED25519, 256, "ssh-ed25519");
    }

    @Test
    void acceptsAGenuineKeyOfEverySupportedType() throws Exception {
        Map<String, String> keys = Map.of(
                "rsa", line(KeyPair.RSA, 2048, "ssh-rsa"),
                "dsa", line(KeyPair.DSA, 1024, "ssh-dss"),
                "ed25519", ed25519(),
                "ed448", line(KeyPair.ED448, 456, "ssh-ed448"),
                "p256", line(KeyPair.ECDSA, 256, "ecdsa-sha2-nistp256"),
                "p384", line(KeyPair.ECDSA, 384, "ecdsa-sha2-nistp384"),
                "p521", line(KeyPair.ECDSA, 521, "ecdsa-sha2-nistp521"));
        keys.forEach((name, key) -> assertTrue(OpenSSHKeyUtil.isWellFormedPublicKey(key), name + ": " + key));
    }

    @Test
    void acceptsAKeyWithoutACommentOrWithSurroundingWhitespace() throws Exception {
        String key = ed25519();
        String bare = key.substring(0, key.lastIndexOf(' '));
        assertTrue(OpenSSHKeyUtil.isWellFormedPublicKey(bare));
        assertTrue(OpenSSHKeyUtil.isWellFormedPublicKey("  " + key + "\n"));
    }

    @Test
    void refusesWhatTheFingerprintCheckAloneLetThrough() throws Exception {
        String key = ed25519();
        String blob = key.split(" ")[1];
        // each of these got a fingerprint and a key type, so was saved and pushed to hosts
        for (String bad : new String[]{
                "ssh-ed25519 notakey",
                "ssh-ed25519 AAAA",
                "ssh-ed25519",
                "ssh-rsa " + blob,                         // label disagrees with the key
                "command=\"echo hi\" " + key,              // authorized_keys options
                "garbage " + key,
                "ssh-ed25519 " + blob + "AAAA",            // trailing bytes after the key
                "ssh-ed25519 " + blob.substring(0, 40),    // truncated
                "ssh-ed25519-cert-v01@openssh.com " + blob}) {
            assertFalse(OpenSSHKeyUtil.isWellFormedPublicKey(bad), bad);
        }
        assertFalse(OpenSSHKeyUtil.isWellFormedPublicKey(null));
        assertFalse(OpenSSHKeyUtil.isWellFormedPublicKey("   "));
    }
}
