/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.model;

import java.sql.Timestamp;

/**
 * Bastillion's SSH certificate authority keypair.
 * <p>
 * The public half is what an operator installs on each managed system as
 * {@code TrustedUserCAKeys}; the private half signs the short-lived certificates Bastillion
 * authenticates with. It is the highest-value secret in the application - anything holding it
 * can mint a login to every host that trusts it - which is why it is never written to disk
 * (see {@link io.bastillion.manage.util.SshCertificateUtil}).
 */
public class CertAuthority {

    /**
     * The authority that signs user certificates, i.e. the one Bastillion logs in with.
     */
    public static final String USER_CA = "USER";

    private Long id;
    private String type = USER_CA;
    private String publicKey;
    private String privateKey;
    private Timestamp createTm;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public Timestamp getCreateTm() {
        return createTm;
    }

    public void setCreateTm(Timestamp createTm) {
        this.createTm = createTm;
    }
}
