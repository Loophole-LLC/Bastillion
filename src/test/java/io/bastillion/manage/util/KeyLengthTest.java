/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * sshKeyLength ships as 256 - a curve size for ecdsa, ignored by ed25519/ed448, and not a
 * usable RSA modulus. Passing it straight through meant sshKeyType=rsa failed key generation
 * and the application did not start at all, despite rsa being a documented option.
 */
class KeyLengthTest {

    @Test
    void rsaFallsBackToTheDocumentedDefaultRatherThanFailing() {
        // The shipped combination that used to abort startup with "Invalid key sizes".
        assertEquals(SSHUtil.RSA_DEFAULT_LENGTH, SSHUtil.resolveKeyLength("rsa", "256"));
        assertEquals(SSHUtil.RSA_DEFAULT_LENGTH, SSHUtil.resolveKeyLength("rsa", null));
        assertEquals(SSHUtil.RSA_DEFAULT_LENGTH, SSHUtil.resolveKeyLength("rsa", "not-a-number"));
    }

    @Test
    void rsaKeepsAUsableConfiguredLength() {
        assertEquals(2048, SSHUtil.resolveKeyLength("rsa", "2048"));
        assertEquals(8192, SSHUtil.resolveKeyLength("rsa", "8192"));
        assertEquals(1024, SSHUtil.resolveKeyLength("rsa", "1024"));
    }

    @Test
    void ecdsaAcceptsOnlyItsCurveSizes() {
        assertEquals(256, SSHUtil.resolveKeyLength("ecdsa", "256"));
        assertEquals(384, SSHUtil.resolveKeyLength("ecdsa", "384"));
        assertEquals(521, SSHUtil.resolveKeyLength("ecdsa", "521"));
        // 4096 is a perfectly good RSA length and not a curve at all
        assertEquals(256, SSHUtil.resolveKeyLength("ecdsa", "4096"));
        assertEquals(256, SSHUtil.resolveKeyLength("ecdsa", "512"));
    }

    @Test
    void edwardsTypesIgnoreTheLength() {
        // jsch fixes the size for these; whatever is configured is simply carried through.
        assertEquals(256, SSHUtil.resolveKeyLength("ed25519", "256"));
        assertEquals(256, SSHUtil.resolveKeyLength("ed448", "256"));
    }

    @Test
    void isCaseAndWhitespaceInsensitive() {
        assertEquals(SSHUtil.RSA_DEFAULT_LENGTH, SSHUtil.resolveKeyLength("  RSA ", "256"));
        assertEquals(256, SSHUtil.resolveKeyLength("ECDSA", "256"));
    }

    @Test
    void anUnknownTypeIsLeftAlone() {
        assertEquals(256, SSHUtil.resolveKeyLength("something-else", "256"));
    }
}
