/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.model;

import java.sql.Timestamp;

/**
 * A host certificate authority Bastillion trusts.
 * <p>
 * A managed system presenting a host certificate signed by one of these is accepted without
 * its individual host key needing to be recorded or approved - the fleet equivalent of a
 * single {@code @cert-authority} line in an OpenSSH known_hosts file. This is the other half
 * of {@link KnownHostKey}: that records one key per host, this trusts whoever signs for them.
 */
public class HostCertAuthority {

    private Long id;
    private String publicKey;
    private String fingerprint;
    private String comment;
    private Timestamp createTm;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public Timestamp getCreateTm() {
        return createTm;
    }

    public void setCreateTm(Timestamp createTm) {
        this.createTm = createTm;
    }
}
