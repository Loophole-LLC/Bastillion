/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.UserInfo;
import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.db.HostCertAuthorityDB;
import io.bastillion.manage.db.HostKeyDB;
import io.bastillion.manage.model.HostCertAuthority;
import io.bastillion.manage.model.KnownHostKey;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.sql.SQLException;
import java.util.List;

/**
 * JSch {@link HostKeyRepository} backed by the {@code host_key} table - Bastillion's
 * known_hosts.
 * <p>
 * Every SSH session used to be opened with {@code StrictHostKeyChecking=no}, which does not
 * mean "warn" - it means the key a host presents is never compared to anything. A bastion is
 * the worst place for that: it hands the host the application private key, and on an
 * authentication fallback the user's own password or key passphrase, so anything that can
 * answer on a managed system's address once can collect credentials for it.
 * <p>
 * Verification mode comes from the {@code hostKeyVerification} property:
 * <ul>
 *   <li>{@code accept-new} (default) - record the key the first time a host is seen and
 *       trust it, then refuse to connect if that host ever presents a different one. Mirrors
 *       OpenSSH's own accept-new. Chosen as the default because it needs no action from an
 *       operator upgrading an existing install, while still closing the case that actually
 *       matters: a key that changes under you.</li>
 *   <li>{@code strict} - additionally require a manager to approve each newly seen host key
 *       before the first connection to it is allowed.</li>
 *   <li>{@code off} - no verification (the pre-6.0.0 behavior).</li>
 * </ul>
 */
public class HostKeyVerifier implements HostKeyRepository {

    private static final Logger log = LoggerFactory.getLogger(HostKeyVerifier.class);

    /**
     * Host key decisions go to the system audit log rather than this class's own logger.
     * Trusting a host key on first sight is a security decision, and the root log level is
     * warn - logged as info on the class logger it would simply not appear, leaving the only
     * record of what Bastillion decided to trust in the database.
     */
    private static final Logger auditLog = LoggerFactory.getLogger("io.bastillion.manage.util.SystemAudit");

    public static final String MODE_OFF = "off";
    public static final String MODE_ACCEPT_NEW = "accept-new";
    public static final String MODE_STRICT = "strict";

    private static final String MODE = AppConfig.getProperty("hostKeyVerification", MODE_ACCEPT_NEW);

    /**
     * @return true unless host key verification is switched off
     */
    public static boolean isEnabled() {
        return !MODE_OFF.equalsIgnoreCase(MODE);
    }

    /**
     * @return true when a newly seen host key needs a manager's approval before first use
     */
    static boolean isStrict() {
        return MODE_STRICT.equalsIgnoreCase(MODE);
    }

    private final JSch jsch;

    public HostKeyVerifier(JSch jsch) {
        this.jsch = jsch;
    }

    /**
     * Compares the key a host just presented against what has been recorded for it.
     * <p>
     * JSch calls this during the handshake and aborts the connection itself on anything but
     * {@link #OK}, so recording a new or changed key here and returning a refusal is what
     * turns the handshake into the audit trail the manage screen reads.
     *
     * @param hostPort the host as JSch formats it: "host", or "[host]:port" off port 22
     * @param key      the raw host key blob the server presented
     */
    @Override
    public int check(String hostPort, byte[] key) {
        HostAddress address = HostAddress.parse(hostPort);
        HostKey offered;
        try {
            offered = new HostKey(hostPort, key);
        } catch (Exception ex) {
            // Not just JSchException: the key blob comes off the wire from the host being
            // verified, and JSch parses its length-prefixed fields without bounds checks, so
            // a truncated or hostile blob surfaces as ArrayIndexOutOfBoundsException. Letting
            // an unchecked exception out of check() would propagate into the handshake
            // instead of refusing the connection.
            log.error("Refusing {}: could not read the host key it presented", hostPort, ex);
            return NOT_INCLUDED;
        }
        String offeredKey = offered.getKey();
        String offeredType = offered.getType();
        String offeredFingerprint = offered.getFingerPrint(jsch);

        try {
            KnownHostKey known = HostKeyDB.getHostKey(address.host(), address.port(), offeredType);

            if (known == null) {
                return recordFirstSighting(address, offeredType, offeredKey, offeredFingerprint);
            }
            return evaluate(known, address, hostPort, offeredType, offeredKey, offeredFingerprint);

        } catch (Exception ex) {
            // Fail closed. An unreadable key store is not a reason to accept an unverified
            // host key on a machine whose job is gating access to other machines.
            log.error("Refusing {}: host key could not be verified", hostPort, ex);
            return NOT_INCLUDED;
        }
    }

    /**
     * Decides what to do about a host key that already has a record.
     */
    private int evaluate(KnownHostKey known, HostAddress address, String hostPort,
                         String offeredType, String offeredKey, String offeredFingerprint)
            throws Exception {
        {
            if (KnownHostKey.REVOKED.equals(known.getStatus())) {
                log.error("Refusing {}: its {} host key ({}) has been revoked",
                        hostPort, offeredType, offeredFingerprint);
                return NOT_INCLUDED;
            }
            if (!offeredKey.equals(known.getPublicKey())) {
                // Record before refusing, so the manage screen can show the approved key and
                // the offered one side by side.
                HostKeyDB.markChanged(address.host(), address.port(), offeredType, offeredKey, offeredFingerprint);
                log.error("Refusing {}: its {} host key changed from {} to {}. Either the host was "
                                + "rebuilt or the connection is being intercepted - a manager must resolve "
                                + "this on the Host Keys screen before Bastillion will connect again.",
                        hostPort, offeredType, known.getFingerprint(), offeredFingerprint);
                return CHANGED;
            }
            if (KnownHostKey.PENDING.equals(known.getStatus())
                    || KnownHostKey.CHANGED.equals(known.getStatus())) {
                log.error("Refusing {}: its {} host key ({}) is awaiting approval on the Host Keys screen",
                        hostPort, offeredType, offeredFingerprint);
                return NOT_INCLUDED;
            }
            return OK;
        }
    }

    /**
     * Stores a host key seen for the first time, trusting it under accept-new and holding it
     * for approval under strict.
     */
    private int recordFirstSighting(HostAddress address, String type, String key, String fingerprint)
            throws Exception {
        String status = isStrict() ? KnownHostKey.PENDING : KnownHostKey.TRUSTED;
        try {
            HostKeyDB.insertHostKey(address.host(), address.port(), type, key, fingerprint, status);
        } catch (SQLException ex) {
            // host_key is unique on (host, port, type), so a second connection opened at the
            // same time to the same unseen host loses this insert. That is not a verification
            // failure - without this it fell through to check()'s catch-all and refused a
            // connection whose key was perfectly good, reporting "could not be verified".
            KnownHostKey raced = HostKeyDB.getHostKey(address.host(), address.port(), type);
            if (raced == null) {
                throw ex;
            }
            log.debug("Another connection recorded the {} host key for {}:{} first",
                    type, address.host(), address.port());
            return evaluate(raced, address, address.host() + ":" + address.port(),
                    type, key, fingerprint);
        }
        if (isStrict()) {
            log.error("Refusing {}:{}: its {} host key ({}) has not been seen before and needs a "
                            + "manager's approval on the Host Keys screen",
                    address.host(), address.port(), type, fingerprint);
            return NOT_INCLUDED;
        }
        auditLog.info("Trusting the {} host key ({}) presented by {}:{} on first sight; connections "
                        + "will be refused if it ever changes",
                type, fingerprint, address.host(), address.port());
        return OK;
    }

    /**
     * JSch calls this after a successful {@link #check} returning OK, and on its own
     * "add this key" prompt flow. Bastillion records keys in {@link #check} instead, where
     * the verification mode is applied - an implicit add here would let a host that failed
     * verification write its own key into the store.
     */
    @Override
    public void add(HostKey hostkey, UserInfo ui) {
        log.debug("Ignoring JSch request to add a host key for {}; keys are recorded during verification",
                hostkey.getHost());
    }

    @Override
    public void remove(String host, String type) {
        remove(host, type, null);
    }

    @Override
    public void remove(String host, String type, byte[] key) {
        log.debug("Ignoring JSch request to remove the {} host key for {}; use the Host Keys screen",
                type, host);
    }

    @Override
    public String getKnownHostsRepositoryID() {
        return "bastillion:host_key";
    }

    /**
     * The markers OpenSSH uses in known_hosts, and that JSch looks for here.
     */
    private static final String MARKER_CERT_AUTHORITY = "@cert-authority";
    private static final String MARKER_REVOKED = "@revoked";

    /**
     * Applies to every host. A trusted host CA is trusted for the whole fleet - the point of
     * having one is not maintaining a list of hosts.
     */
    private static final String ALL_HOSTS = "*";

    /**
     * Where JSch collects trusted host certificate authorities and revoked keys from.
     * <p>
     * When a host presents a host certificate rather than a bare key, {@code Session} hands
     * verification to {@code OpenSshCertificateHostKeyVerifier} and returns - {@link #check}
     * is never called for that connection. That verifier reads the trusted CAs by calling
     * this method and keeping the entries marked {@code @cert-authority}, and the revoked keys
     * by keeping those marked {@code @revoked}. So returning an empty array here, as this did
     * before, meant a host certificate could never be trusted no matter what was recorded.
     * <p>
     * Revoked host keys are published as {@code @revoked} so that a key a manager distrusted
     * is refused on the certificate path too, not just by {@link #check}.
     */
    @Override
    public HostKey[] getHostKey() {
        List<HostKey> entries = new ArrayList<>();
        try {
            for (HostCertAuthority authority : HostCertAuthorityDB.getHostCertAuthorities()) {
                HostKey entry = toHostKey(MARKER_CERT_AUTHORITY, ALL_HOSTS, authority.getPublicKey(),
                        authority.getComment());
                if (entry != null) {
                    entries.add(entry);
                }
            }
            for (KnownHostKey revoked : HostKeyDB.getRevokedHostKeys()) {
                HostKey entry = toHostKey(MARKER_REVOKED, revoked.getHost(),
                        revoked.getType() + " " + revoked.getPublicKey(), "revoked");
                if (entry != null) {
                    entries.add(entry);
                }
            }
        } catch (Exception ex) {
            // Returning nothing means "no CA is trusted", which refuses certificates rather
            // than accepting them - the safe direction for an unreadable store.
            log.error("Could not read trusted host certificate authorities", ex);
        }
        return entries.toArray(new HostKey[0]);
    }

    /**
     * Builds a JSch {@link HostKey} from an authorized_keys-form public key, or null if it
     * cannot be parsed.
     */
    private HostKey toHostKey(String marker, String host, String opensshPublicKey, String comment) {
        try {
            String[] fields = opensshPublicKey.trim().split("\\s+");
            if (fields.length < 2) {
                log.error("Ignoring malformed {} entry for {}", marker, host);
                return null;
            }
            byte[] blob = java.util.Base64.getDecoder().decode(fields[1]);
            return new HostKey(marker, host, HostKey.GUESS, blob, comment);
        } catch (Exception ex) {
            log.error("Ignoring unreadable {} entry for {}", marker, host, ex);
            return null;
        }
    }

    /**
     * JSch uses this to decide which key algorithms to offer for a host, so returning the
     * recorded key lets the handshake prefer the algorithm already trusted for it.
     */
    @Override
    public HostKey[] getHostKey(String hostPort, String type) {
        if (hostPort == null) {
            return new HostKey[0];
        }
        HostAddress address = HostAddress.parse(hostPort);
        try {
            List<String> types = StringUtils.isEmpty(type)
                    ? List.of("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "ssh-rsa")
                    : List.of(type);
            for (String candidate : types) {
                KnownHostKey known = HostKeyDB.getHostKey(address.host(), address.port(), candidate);
                if (known != null && KnownHostKey.TRUSTED.equals(known.getStatus())) {
                    // public_key is stored in the base64 form HostKey.getKey() returns; this
                    // constructor parses the raw wire blob, so it has to be decoded back.
                    byte[] blob = java.util.Base64.getDecoder().decode(known.getPublicKey());
                    return new HostKey[]{new HostKey(hostPort, blob)};
                }
            }
        } catch (Exception ex) {
            log.error("Could not read recorded host keys for {}", hostPort, ex);
        }
        return new HostKey[0];
    }

    /**
     * A host as JSch hands it to a {@link HostKeyRepository}: bare for the default SSH port,
     * or bracketed with an explicit port otherwise ("[db01.example.com]:2222").
     */
    record HostAddress(String host, int port) {

        private static final int DEFAULT_SSH_PORT = 22;

        static HostAddress parse(String hostPort) {
            if (hostPort == null) {
                return new HostAddress("", DEFAULT_SSH_PORT);
            }
            if (hostPort.startsWith("[")) {
                String host = StringUtils.substringBetween(hostPort, "[", "]");
                String port = StringUtils.substringAfterLast(hostPort, "]:");
                if (host != null && StringUtils.isNumeric(port)) {
                    return new HostAddress(host, Integer.parseInt(port));
                }
            }
            return new HostAddress(hostPort, DEFAULT_SSH_PORT);
        }
    }
}
