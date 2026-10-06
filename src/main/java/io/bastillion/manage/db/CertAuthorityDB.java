/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import com.jcraft.jsch.KeyPair;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.EncryptionUtil;
import io.bastillion.manage.util.SSHUtil;
import io.bastillion.manage.util.SshCertificateUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;

/**
 * DAO for Bastillion's SSH certificate authority keypair.
 * <p>
 * Mirrors {@link PrivateKeyDB}: one row, private half encrypted at the column level by
 * {@link EncryptionUtil}, read fresh on use so a rotation takes effect without a restart.
 */
public class CertAuthorityDB {

    // There is deliberately no rotate() here. Replacing the keypair in one step invalidates
    // every certificate the old key signed the moment it runs, while the hosts still trust
    // only the old CA - so connections fail until the new public key has been installed
    // everywhere. Doing it safely means serving both keys at once (hosts accept several in
    // TrustedUserCAKeys) and retiring the old one after the fleet has caught up, which is a
    // feature rather than a method. An unreachable one-step version was worse than none.

    private CertAuthorityDB() {
    }

    /**
     * @return the certificate authority keypair, or null if none has been generated
     */
    public static CertAuthority getCertAuthority(String type) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "select * from cert_authority where type = ?")) {
            stmt.setString(1, type);
            try (ResultSet rs = stmt.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                CertAuthority ca = new CertAuthority();
                ca.setId(rs.getLong("id"));
                ca.setType(rs.getString("type"));
                ca.setPublicKey(rs.getString("public_key"));
                ca.setPrivateKey(EncryptionUtil.decrypt(rs.getString("private_key")));
                ca.setCreateTm(rs.getTimestamp("create_tm"));
                return ca;
            }
        }
    }

    /**
     * Generates and stores a certificate authority keypair if none exists yet.
     * <p>
     * Generated up front rather than on first use, because the public half has to be installed
     * on every managed system before certificate authentication can be switched on - an
     * operator cannot adopt the feature without being able to see the key first.
     *
     * @return the public key if one was generated, or null if an authority already existed
     */
    public static String generateIfAbsent(String type)
            throws SQLException, GeneralSecurityException, IOException {
        if (getCertAuthority(type) != null) {
            return null;
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair kp = kpg.generateKeyPair();
        String privateKey = SSHUtil.buildOpenSSHPrivateKey(kp, KeyPair.ED25519);
        String publicKey = SshCertificateUtil.ED25519_KEY_TYPE + " "
                + Base64.getEncoder().encodeToString(SSHUtil.encodeSSHPublicKey(
                        SshCertificateUtil.ED25519_KEY_TYPE, kp.getPublic().getEncoded()))
                + " bastillion-" + type.toLowerCase() + "-ca";

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "insert into cert_authority (type, public_key, private_key) values (?,?,?)")) {
            stmt.setString(1, type);
            stmt.setString(2, publicKey);
            stmt.setString(3, EncryptionUtil.encrypt(privateKey));
            stmt.executeUpdate();
        }
        return publicKey;
    }

    /**
     * Allocates the next certificate serial.
     * <p>
     * sshd logs the serial next to the key id on every accepted connection, and it is what a
     * key revocation list revokes, so each issued certificate needs its own. Read and increment
     * have to be one atomic step: {@code synchronized} covers the single JVM this runs in (the
     * server is embedded - see io.bastillion.Main), and the transaction covers the statements.
     */
    public static synchronized long nextSerial(String type) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn()) {
            boolean autoCommit = con.getAutoCommit();
            con.setAutoCommit(false);
            try {
                try (PreparedStatement stmt = con.prepareStatement(
                        "update cert_authority set next_serial = next_serial + 1 where type = ?")) {
                    stmt.setString(1, type);
                    stmt.executeUpdate();
                }
                try (PreparedStatement stmt = con.prepareStatement(
                        "select next_serial from cert_authority where type = ?")) {
                    stmt.setString(1, type);
                    try (ResultSet rs = stmt.executeQuery()) {
                        long serial = rs.next() ? rs.getLong(1) : 1L;
                        con.commit();
                        return serial;
                    }
                }
            } catch (SQLException ex) {
                con.rollback();
                throw ex;
            } finally {
                con.setAutoCommit(autoCommit);
            }
        }
    }
}
