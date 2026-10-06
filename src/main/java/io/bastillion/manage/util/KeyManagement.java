/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.common.util.AppConfig;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * How much of a managed system's {@code authorized_keys} file Bastillion takes responsibility
 * for.
 * <p>
 * This is a separate question from how Bastillion authenticates. {@link SshCertificateAuth}
 * decides whether it presents a certificate or a bare key; this decides whether anything gets
 * written to the host at all. The two are orthogonal, and the common arrangement is
 * certificates for Bastillion's own sessions while users' keys are still distributed so they
 * can reach a host directly.
 */
public final class KeyManagement {

    private static final Logger log = LoggerFactory.getLogger(KeyManagement.class);

    public enum Mode {
        /**
         * Bastillion owns the file: it is replaced with the public keys of every user assigned
         * to that system, plus Bastillion's own. Revoking a user's key here removes their
         * direct access to the host on the next refresh.
         */
        MANAGE,

        /**
         * Bastillion leaves the file alone except for making sure its own key is in it. User
         * keys are not distributed, so direct access is whatever the host already allows.
         */
        APPEND,

        /**
         * Bastillion never reads or writes the file. Only usable when it can authenticate
         * some other way - in practice {@code sshCertificateAuth=on} with the authority
         * installed on every host, since otherwise there is nothing for it to log in with.
         */
        OFF
    }

    private static final Mode MODE = resolve(
            AppConfig.getProperty("keyManagement"),
            AppConfig.getProperty("keyManagementEnabled"));

    private KeyManagement() {
    }

    public static Mode mode() {
        return MODE;
    }

    /**
     * @return true when user public keys are distributed to hosts, i.e. {@link Mode#MANAGE}
     * <p>
     * Also gates the authorized-key refresh timer and the "Manage SSH Keys" screens: with
     * nothing being distributed there is nothing for them to do.
     */
    public static boolean distributesUserKeys() {
        return MODE == Mode.MANAGE;
    }

    /**
     * @return true when Bastillion may write a host's authorized_keys at all
     */
    public static boolean writesAuthorizedKeys() {
        return MODE != Mode.OFF;
    }

    /**
     * Resolves the mode, honouring the older boolean {@code keyManagementEnabled} when the
     * three-way {@code keyManagement} is not set.
     * <p>
     * Package-private and taking both values as arguments so the precedence can be tested
     * without the properties they normally come from.
     *
     * @param configured    the {@code keyManagement} setting: manage, append or off
     * @param legacyEnabled the older {@code keyManagementEnabled} boolean, which "append" and
     *                      "manage" replace - still honoured so an existing instance that set
     *                      it to false does not silently start managing files
     */
    static Mode resolve(String configured, String legacyEnabled) {
        if (StringUtils.isNotBlank(configured)) {
            switch (configured.trim().toLowerCase()) {
                case "manage":
                    return Mode.MANAGE;
                case "append":
                    return Mode.APPEND;
                case "off":
                    return Mode.OFF;
                default:
                    // Deliberately not fatal, and deliberately not OFF: a typo here must not
                    // quietly stop Bastillion maintaining the files it has been maintaining.
                    log.error("Unrecognized keyManagement value '{}'; expected manage, append or off. "
                            + "Falling back to keyManagementEnabled.", configured);
            }
        }
        // Mirror the old test exactly rather than inverting it. The code this replaced was
        // "true".equals(keyManagementEnabled), so every other value - 0, no, off, an explicitly
        // blank one - meant append-only. Treating just "false" as append would have upgraded
        // all of those to full management, and the next refresh pass would replace
        // authorized_keys on every host with the list Bastillion knows about, dropping every
        // key it does not. Null is different: it means the setting is absent altogether rather
        // than set to something, which is a fresh install taking the shipped default.
        if (legacyEnabled == null) {
            return Mode.MANAGE;
        }
        return "true".equalsIgnoreCase(legacyEnabled.trim()) ? Mode.MANAGE : Mode.APPEND;
    }
}
