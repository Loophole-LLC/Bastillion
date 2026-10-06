/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.db.CertAuthorityDB;
import io.bastillion.manage.db.PrivateKeyDB;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.model.ApplicationKey;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.SortedSet;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;
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
     * Beyond this, the certificate lifetime stops being a usable substitute for revocation.
     * <p>
     * Nothing here publishes a key revocation list, so an issued certificate is valid until
     * it expires no matter what happens in Bastillion afterwards. At the default of 300s that
     * is barely a distinction - disable an account and their certificates are dead within five
     * minutes. Stretch it to a working day and "remove this user" quietly stops meaning "cut
     * off their access", which is the kind of change that should be deliberate.
     */
    private static final long VALIDITY_WARN_THRESHOLD_SECONDS = 3600;

    /**
     * Lifetime of a certificate a user downloads for their own SSH client. Necessarily longer
     * than the per-connection one - a credential you fetch by hand has to outlive the fetch -
     * and deliberately not the same setting, so stretching one does not stretch the other.
     * Eight hours is one working session: re-downloading each morning is tolerable, every
     * couple of hours is not.
     */
    private static final long USER_VALIDITY_SECONDS =
            Long.parseLong(AppConfig.getProperty("sshUserCertificateValiditySeconds", "28800"));

    /**
     * Past a working day, re-downloading stops being the re-authorization check that makes
     * expiry stand in for revocation.
     */
    private static final long USER_VALIDITY_WARN_THRESHOLD_SECONDS = 43200;

    /**
     * @return a warning about the configured user certificate lifetime, or null
     */
    public static String excessiveUserValidityWarning() {
        if (USER_VALIDITY_SECONDS <= USER_VALIDITY_WARN_THRESHOLD_SECONDS) {
            return null;
        }
        return "sshUserCertificateValiditySeconds is " + USER_VALIDITY_SECONDS + ". A downloaded "
                + "certificate keeps working until it expires, so revoking a user's profile stops "
                + "taking effect immediately - and those sessions reach the host directly, so they "
                + "are not in Bastillion's session audit either. Keep this to a working session "
                + "(the default is 28800) unless you have another way to revoke.";
    }

    /**
     * Signs a certificate for a user's own SSH client, so they can reach a host directly
     * without their public key being in its authorized_keys.
     * <p>
     * Principals are the distinct login accounts the user can currently reach through their
     * profiles, read at issue time - which is what makes re-downloading the re-authorization
     * check, and why the lifetime matters.
     * <p>
     * Note what a certificate cannot express: principals are usernames, with no host in them.
     * A certificate naming "deploy" is accepted as deploy@ on <em>every</em> host that trusts
     * this authority, not only the ones in the user's profiles. Where that is too broad, hosts
     * need an AuthorizedPrincipalsFile deciding which principals they accept - see the README.
     *
     * @param userPublicKey the user's own public key, in authorized_keys form
     * @param userId        the Bastillion user it is for
     * @param username      recorded as the certificate key id, which the host logs
     * @return the certificate in authorized_keys form
     */
    public static String userCertificateFor(String userPublicKey, Long userId, String username)
            throws SQLException, GeneralSecurityException {
        CertAuthority ca = CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA);
        if (ca == null) {
            throw new GeneralSecurityException("No certificate authority has been generated yet.");
        }
        String unsupported = unsupportedKeyTypeReason(userPublicKey, "key");
        if (unsupported != null) {
            throw new GeneralSecurityException(unsupported);
        }

        List<String> principals = loginAccountsFor(userId);
        if (principals.isEmpty()) {
            throw new GeneralSecurityException(
                    "You have no systems assigned, so there is no account to issue a certificate for.");
        }

        long serial = CertAuthorityDB.nextSerial(CertAuthority.USER_CA);
        String keyId = "bastillion:" + (StringUtils.isBlank(username) ? "user" : username);
        String certificate = SshCertificateUtil.signUserCertificate(
                ca.getPrivateKey(), ca.getPublicKey(), userPublicKey,
                keyId, principals, serial, USER_VALIDITY_SECONDS);

        auditLog.info("Issued user SSH certificate serial {} id '{}' for principals {} valid {}s",
                serial, keyId, principals, USER_VALIDITY_SECONDS);
        return certificate;
    }

    /**
     * The distinct login accounts this user can reach through their profiles.
     */
    private static List<String> loginAccountsFor(Long userId) throws SQLException, GeneralSecurityException {
        Set<String> accounts = new LinkedHashSet<>();
        SortedSet systems = SystemDB.getUserSystemSet(new SortedSet(), userId);
        if (systems.getItemList() != null) {
            for (Object item : systems.getItemList()) {
                String account = ((HostSystem) item).getUser();
                if (StringUtils.isNotBlank(account)) {
                    accounts.add(account);
                }
            }
        }
        return new ArrayList<>(accounts);
    }

    /**
     * @return a warning about the configured certificate lifetime, or null if it is short
     * enough to serve as its own revocation
     */
    public static String excessiveValidityWarning() {
        if (!isEnabled() || VALIDITY_SECONDS <= VALIDITY_WARN_THRESHOLD_SECONDS) {
            return null;
        }
        return "sshCertificateValiditySeconds is " + VALIDITY_SECONDS + ". Bastillion issues a "
                + "certificate per connection and publishes no revocation list, so a certificate "
                + "stays usable until it expires - disabling a user does not cut off access they "
                + "have already been issued until then. Keep this short (the default is 300) "
                + "unless you have another way to revoke.";
    }

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
        return unsupportedKeyTypeReason(applicationPublicKey, "application SSH key");
    }

    /**
     * @param label how to refer to the key in the message ("application SSH key", "key")
     */
    public static String unsupportedKeyTypeReason(String publicKey, String label) {
        String keyType = SSHUtil.getKeyType(publicKey);
        if (keyType == null) {
            // getKeyType returns null for a key JSch cannot load at all. Reading that as "no
            // problem here" suppressed the startup warning this exists to emit and sent the
            // per-system test off blaming a missing certificate authority.
            return "The " + label + " could not be read, so no certificate can be issued for it. "
                    + "Check that it is a valid Ed25519 public key.";
        }
        if (SshCertificateUtil.ED25519_KEY_TYPE.equalsIgnoreCase("ssh-" + keyType)) {
            return null;
        }
        return "The " + label + " is " + keyType + ", but certificates can only be issued for "
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
