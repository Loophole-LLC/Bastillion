/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.manage.util.KeyManagement.Mode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The precedence between the three-way {@code keyManagement} setting and the older boolean
 * {@code keyManagementEnabled} it supersedes. An existing instance that set the boolean must
 * keep the behaviour it had, since the alternative is Bastillion silently starting or
 * stopping to rewrite authorized_keys files on an upgrade.
 */
class KeyManagementTest {

    @Test
    void theThreeWaySettingWinsWhenItIsSet() {
        assertEquals(Mode.MANAGE, KeyManagement.resolve("manage", null));
        assertEquals(Mode.APPEND, KeyManagement.resolve("append", null));
        assertEquals(Mode.OFF, KeyManagement.resolve("off", null));
    }

    @Test
    void theThreeWaySettingOverridesTheOlderBoolean() {
        assertEquals(Mode.OFF, KeyManagement.resolve("off", "true"));
        assertEquals(Mode.MANAGE, KeyManagement.resolve("manage", "false"));
    }

    @Test
    void isCaseAndWhitespaceInsensitive() {
        assertEquals(Mode.OFF, KeyManagement.resolve("  OFF  ", null));
        assertEquals(Mode.APPEND, KeyManagement.resolve("Append", null));
    }

    @Test
    void fallsBackToTheOlderBooleanWhenUnset() {
        // An instance that explicitly set keyManagementEnabled=false keeps append behaviour.
        assertEquals(Mode.APPEND, KeyManagement.resolve(null, "false"));
        assertEquals(Mode.APPEND, KeyManagement.resolve("", "false"));
        assertEquals(Mode.APPEND, KeyManagement.resolve("   ", "FALSE"));

        assertEquals(Mode.MANAGE, KeyManagement.resolve(null, "true"));
        assertEquals(Mode.MANAGE, KeyManagement.resolve("", "true"));
    }

    @Test
    void defaultsToManageWhenNothingIsSet() {
        assertEquals(Mode.MANAGE, KeyManagement.resolve(null, null));
        assertEquals(Mode.MANAGE, KeyManagement.resolve("", ""));
    }

    @Test
    void anUnrecognizedValueFallsBackRatherThanDisablingWrites() {
        // A typo must not quietly stop Bastillion maintaining files it has been maintaining,
        // and must certainly not be read as "off".
        assertEquals(Mode.MANAGE, KeyManagement.resolve("manged", null));
        assertEquals(Mode.MANAGE, KeyManagement.resolve("disabled", "true"));
        assertEquals(Mode.APPEND, KeyManagement.resolve("nonsense", "false"));
    }

    @Test
    void onlyManageDistributesUserKeys() {
        // What gates the refresh timer, the distribution loops, and the Manage SSH Keys
        // screens - all of which have nothing to do in the other two modes.
        assertEquals(Mode.MANAGE, KeyManagement.resolve("manage", null));
        assertFalse(Mode.APPEND == Mode.MANAGE);
        assertFalse(Mode.OFF == Mode.MANAGE);
    }

    @Test
    void theDefaultBuildConfigurationStillManagesKeys() {
        // The bundled BastillionConfig.properties ships keyManagementEnabled=true and an empty
        // keyManagement, so nothing changes for an instance that sets neither.
        assertEquals(Mode.MANAGE, KeyManagement.mode());
        assertTrue(KeyManagement.distributesUserKeys());
        assertTrue(KeyManagement.writesAuthorizedKeys());
        assertTrue(SSHUtil.keyManagementEnabled);
    }
}
