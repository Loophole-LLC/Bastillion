/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.model;

/**
 * An SSH host key Bastillion has seen a managed system present, and what it has decided
 * about it. One row per host, port and key type.
 * <p>
 * Named for the OpenSSH known_hosts file this replaces the absence of - deliberately not
 * "HostKey", which is both {@link com.jcraft.jsch.HostKey} and one letter from
 * {@link HostSystem}.
 */
public class KnownHostKey {

    /**
     * Approved. Connections to this host proceed only while it presents this key.
     */
    public static final String TRUSTED = "TRUSTED";

    /**
     * Seen for the first time and awaiting a manager's approval. Connections are refused.
     * Only reachable under {@code hostKeyVerification=strict}.
     */
    public static final String PENDING = "PENDING";

    /**
     * The host presented a key other than the trusted one. Connections are refused until a
     * manager resolves it. The key actually offered is kept in {@link #getOfferedPublicKey()}
     * so it can be compared against the trusted one rather than silently overwriting it.
     */
    public static final String CHANGED = "CHANGED";

    /**
     * Explicitly distrusted by a manager. Connections are refused.
     */
    public static final String REVOKED = "REVOKED";

    private Long id;
    private String host;
    private Integer port;
    private String type;
    private String publicKey;
    private String fingerprint;
    private String status = TRUSTED;
    private String offeredPublicKey;
    private String offeredFingerprint;
    private java.sql.Timestamp firstSeenTm;
    private java.sql.Timestamp approvedTm;
    private String approvedBy;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getOfferedPublicKey() {
        return offeredPublicKey;
    }

    public void setOfferedPublicKey(String offeredPublicKey) {
        this.offeredPublicKey = offeredPublicKey;
    }

    public String getOfferedFingerprint() {
        return offeredFingerprint;
    }

    public void setOfferedFingerprint(String offeredFingerprint) {
        this.offeredFingerprint = offeredFingerprint;
    }

    public java.sql.Timestamp getFirstSeenTm() {
        return firstSeenTm;
    }

    public void setFirstSeenTm(java.sql.Timestamp firstSeenTm) {
        this.firstSeenTm = firstSeenTm;
    }

    public java.sql.Timestamp getApprovedTm() {
        return approvedTm;
    }

    public void setApprovedTm(java.sql.Timestamp approvedTm) {
        this.approvedTm = approvedTm;
    }

    public String getApprovedBy() {
        return approvedBy;
    }

    public void setApprovedBy(String approvedBy) {
        this.approvedBy = approvedBy;
    }

    /**
     * @return true while this key blocks connections to its host
     */
    public boolean isBlocking() {
        return !TRUSTED.equals(status);
    }
}
