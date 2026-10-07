package io.bastillion.common.util;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppConfigTest {

    @Test
    void toScreamingSnakeCaseSplittingAcronymsProducesTheNameOperatorsActuallyWrite() {
        // The single-rule conversion glues a run of capitals to the word after it, so the
        // names the README documents - and that anyone would guess - did not resolve at all.
        assertEquals("DEFAULT_SSH_PASSPHRASE",
                AppConfig.toScreamingSnakeCaseSplittingAcronyms("defaultSSHPassphrase"));
        assertEquals("RESET_APPLICATION_SSH_KEY",
                AppConfig.toScreamingSnakeCaseSplittingAcronyms("resetApplicationSSHKey"));
        assertEquals("CLIENT_IP_HEADER",
                AppConfig.toScreamingSnakeCaseSplittingAcronyms("clientIPHeader"));
    }

    @Test
    void toScreamingSnakeCaseSplittingAcronymsLeavesOrdinaryNamesAlone() {
        assertEquals("LICENSE_KEY", AppConfig.toScreamingSnakeCaseSplittingAcronyms("licenseKey"));
        assertEquals("DB_USER", AppConfig.toScreamingSnakeCaseSplittingAcronyms("dbUser"));
        assertEquals("SSH_KEY_TYPE", AppConfig.toScreamingSnakeCaseSplittingAcronyms("sshKeyType"));
        assertEquals("MAX_LOGIN_ATTEMPTS_PER_IP",
                AppConfig.toScreamingSnakeCaseSplittingAcronyms("maxLoginAttemptsPerIP"));
        assertEquals("A", AppConfig.toScreamingSnakeCaseSplittingAcronyms("a"));
    }

    @Test
    void bothEnvVarSpellingsStayDistinctWhereAcronymsAreInvolved() {
        // The historical spelling is still accepted, so an operator who already set it keeps
        // working; these are the two names getProperty looks up.
        assertEquals("DEFAULT_SSHPASSPHRASE", AppConfig.toScreamingSnakeCase("defaultSSHPassphrase"));
        assertEquals("DEFAULT_SSH_PASSPHRASE",
                AppConfig.toScreamingSnakeCaseSplittingAcronyms("defaultSSHPassphrase"));
    }

    @Test
    void toScreamingSnakeCaseConvertsCamelCase() {
        assertEquals("LICENSE_KEY", AppConfig.toScreamingSnakeCase("licenseKey"));
        assertEquals("DB_USER", AppConfig.toScreamingSnakeCase("dbUser"));
        assertEquals("SSH_KEY_TYPE", AppConfig.toScreamingSnakeCase("sshKeyType"));
        assertEquals("A", AppConfig.toScreamingSnakeCase("a"));
        // No case transitions -> no underscores inserted, just uppercased.
        assertEquals("ALLLOWERCASE", AppConfig.toScreamingSnakeCase("alllowercase"));
    }

    @Test
    void getPropertyFallsBackToBundledDefaultWhenUnset() {
        // deleteAuditLogAfter=90 in the bundled BastillionConfig.properties, and there's no
        // CONFIG_DIR-persisted override or env var for it in a fresh test run.
        assertEquals("90", AppConfig.getProperty("deleteAuditLogAfter"));
    }

    @Test
    void getPropertyReturnsNullForCompletelyUnknownName() {
        assertNull(AppConfig.getProperty("thisPropertyDoesNotExistAnywhere"));
    }

    @Test
    void getPropertyWithDefaultValueUsesDefaultOnlyWhenUnset() {
        assertEquals("fallback", AppConfig.getProperty("thisPropertyDoesNotExistAnywhere", "fallback"));
        // A property that does resolve (via bundled defaults) should win over the fallback.
        assertEquals("90", AppConfig.getProperty("deleteAuditLogAfter", "fallback"));
    }

    @Test
    void getPropertyWithReplacementMapSubstitutesPlaceholders() {
        Map<String, String> replacements = new HashMap<>();
        replacements.put("randomPassphrase", "generated-value");
        // defaultSSHPassphrase=${randomPassphrase} in the bundled defaults.
        assertEquals("generated-value", AppConfig.getProperty("defaultSSHPassphrase", replacements));
    }

    @Test
    void encryptDecryptPropertyRoundTrips() throws Exception {
        AppConfig.encryptProperty("appConfigTestRoundTrip", "s3cr3t-value");
        assertTrue(AppConfig.isPropertyEncrypted("appConfigTestRoundTrip"));
        assertEquals("s3cr3t-value", AppConfig.decryptProperty("appConfigTestRoundTrip"));
    }

    @Test
    void isPropertyEncryptedFalseForPlainValues() {
        assertFalse(AppConfig.isPropertyEncrypted("dbDriver"));
    }
}
