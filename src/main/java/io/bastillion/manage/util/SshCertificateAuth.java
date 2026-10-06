/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.db.CertAuthorityDB;
import io.bastillion.manage.db.PrivateKeyDB;
import io.bastillion.manage.model.ApplicationKey;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.model.HostSystem;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * The {@code sshCertificateAuth} feature switch, and the one place a certificate is issued
 * for an outgoing SSH connection.
 * <p>
 * Splits from {@link SshCertificateUtil}, which only knows how to encode and sign a
 * certificate: this decides whether to issue one at all, what to put in it, and where the
 * keys come from.
 * <p>
 * What it buys, beyond not having to distribute keys: sshd logs the certificate's key id on
 * every accepted connection. Bastillion authenticates to every managed system with one shared
 * application key, so until now a host's own logs could not tell which Bastillion user was
 * responsible for a session - only Bastillion's audit trail could, and only if you had it. A
 * key id of {@code bastillion:<username>} puts that attribution in the host's auth log.
 */
public class SshCertificateAuth {

    private static final Logger log = LoggerFactory.getLogger(SshCertificateAuth.class);
    private static final Logger auditLog = LoggerFactory.getLogger("io.bastillion.manage.util.SystemAudit");

    private static final String MODE = AppConfig.getProperty("sshCertificateAuth", "off");
    private static final long VALIDITY_SECONDS =
            Long.parseLong(AppConfig.getProperty("sshCertificateValiditySeconds", "300"));

    /**
     * Used when there is no Bastillion user behind the connection - the authorized-key refresh
     * timer, or registering a system.
     */
    static final String SYSTEM_PRINCIPAL_ID = "bastillion:system";

    private SshCertificateAuth() {
    }

    /**
     * Why this application key cannot be certified, or null if it can.
     * <p>
     * Certificates attest to the key the session authenticates with, which is the application
     * key, and {@link SshCertificateUtil} signs Ed25519 only. {@code sshKeyType} also accepts
     * rsa, ecdsa and ed448, so this is a supported configuration that certificates cannot work
     * with - and every symptom of it points somewhere else: connections keep succeeding,
     * because issuing falls back to plain key authentication. Checked in one place so the
     * startup warning, the fallback log line and the per-system test all name the real cause.
     */
    public static String unsupportedKeyTypeReason(String applicationPublicKey) {
        String keyType = SSHUtil.getKeyType(applicationPublicKey);
        if (keyType == null || SshCertificateUtil.ED25519_KEY_TYPE.equalsIgnoreCase("ssh-" + keyType)) {
            return null;
        }
        return "The application SSH key is " + keyType + ", but certificates can only be issued for "
                + "an Ed25519 key. Set sshKeyType=ed25519 and replace the application key "
                + "(Settings -> Replace application SSH key), or leave sshCertificateAuth off.";
    }

    /**
     * @return true when Bastillion should authenticate with a certificate it signs rather than
     * relying on its public key being in the target's authorized_keys
     */
    public static boolean isEnabled() {
        return "on".equalsIgnoreCase(MODE) || "true".equalsIgnoreCase(MODE);
    }

    /**
     * Signs a certificate for this connection, or returns null if certificate authentication
     * is off or cannot be used.
     * <p>
     * The certificate certifies the application key's own public key, because that is the key
     * the SSH session authenticates with - a certificate is an attestation about a key, not a
     * replacement for one.
     *
     * @param hostSystem the system being connected to; its login account becomes the
     *                   certificate principal, since sshd requires a principal matching the
     *                   account being logged into unless an AuthorizedPrincipalsFile says
     *                   otherwise, and requiring one of those would make this unusable
     *                   without further per-host setup
     * @param username   the Bastillion user the connection is for, recorded as the key id for
     *                   the host's own logs; null for Bastillion's own background work
     * @return the certificate in authorized_keys form, or null to fall back to plain key auth
     */
    public static String certificateFor(HostSystem hostSystem, String username) {
        if (!isEnabled()) {
            return null;
        }
        return issueCertificate(hostSystem, username);
    }

    /**
     * Issues the certificate, with the feature switch already decided by the caller.
     * <p>
     * Separate from {@link #certificateFor} so the issuing itself can be exercised without the
     * {@code sshCertificateAuth} property, which is read once at class-load time.
     */
    static String issueCertificate(HostSystem hostSystem, String username) {
        try {
            CertAuthority ca = CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA);
            if (ca == null) {
                log.error("sshCertificateAuth is on but no certificate authority has been generated; "
                        + "falling back to plain public key authentication");
                return null;
            }
            ApplicationKey appKey = PrivateKeyDB.getApplicationKey();
            if (appKey == null) {
                return null;
            }
            String unsupported = unsupportedKeyTypeReason(appKey.getPublicKey());
            if (unsupported != null) {
                log.error("{} Falling back to plain public key authentication.", unsupported);
                return null;
            }

            String keyId = StringUtils.isBlank(username) ? SYSTEM_PRINCIPAL_ID : "bastillion:" + username;
            long serial = CertAuthorityDB.nextSerial(CertAuthority.USER_CA);

            String certificate = SshCertificateUtil.signUserCertificate(
                    ca.getPrivateKey(), ca.getPublicKey(), appKey.getPublicKey(),
                    keyId, principalsFor(hostSystem), serial, VALIDITY_SECONDS);

            auditLog.info("Issued SSH certificate serial {} id '{}' for {}@{}:{} valid {}s",
                    serial, keyId, hostSystem.getUser(), hostSystem.getHost(), hostSystem.getPort(),
                    VALIDITY_SECONDS);
            return certificate;

        } catch (Exception ex) {
            // Falling back to the application key keeps a signing problem from locking every
            // system out at once. It is a downgrade, so it is logged as an error rather than
            // passed over - and it only works where the application key is still in
            // authorized_keys, which is exactly the configuration this replaces.
            log.error("Could not issue an SSH certificate for {}:{}; falling back to plain public "
                    + "key authentication", hostSystem.getHost(), hostSystem.getPort(), ex);
            return null;
        }
    }

    /**
     * sshd accepts a certificate when any of its principals matches the account being logged
     * into, so the target account has to be among them.
     */
    private static List<String> principalsFor(HostSystem hostSystem) throws GeneralSecurityException {
        if (StringUtils.isBlank(hostSystem.getUser())) {
            throw new GeneralSecurityException("the system has no login account to issue a certificate for");
        }
        List<String> principals = new ArrayList<>();
        principals.add(hostSystem.getUser());
        return principals;
    }
}
