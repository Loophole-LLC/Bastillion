/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.ApplicationKey;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.EncryptionUtil;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * DAO that returns public / private key for the system generated private key
 */
public class PrivateKeyDB {

    private PrivateKeyDB() {
    }

    /**
     * returns public private key for application
     *
     * @return app key values
     */
    public static ApplicationKey getApplicationKey() throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getApplicationKey(con);
        }
    }

    /**
     * returns public private key for application
     *
     * @param con DB connection
     * @return app key values
     */
    public static ApplicationKey getApplicationKey(Connection con) throws SQLException, GeneralSecurityException {

        ApplicationKey appKey = null;

        try (PreparedStatement stmt = con.prepareStatement("select * from  application_key");
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {

                appKey = new ApplicationKey();
                appKey.setId(rs.getLong("id"));
                appKey.setPassphrase(EncryptionUtil.decrypt(rs.getString("passphrase")));
                appKey.setPrivateKey(EncryptionUtil.decrypt(rs.getString("private_key")));
                appKey.setPublicKey(rs.getString("public_key"));

            }
        }

        return appKey;
    }

    /**
     * Replaces the application's SSH keypair (the one key every registered system trusts)
     * with the given values, encrypting private_key/passphrase the same way the initial
     * DBInitServlet-generated key is. Takes effect immediately - callers like
     * SSHUtil.authAndAddPubKey() read this table fresh on every connection, nothing is
     * cached, so no restart is needed. Callers must validate the keypair actually loads
     * (see SSHUtil.validateKeyPair) before calling this - an unvalidated bad paste here
     * would break every future SSH connection until fixed.
     */
    public static void updateApplicationKey(String publicKey, String privateKey, String passphrase)
            throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            updateApplicationKey(con, publicKey, privateKey, passphrase);
        }
    }

    /**
     * Replaces the application's SSH keypair (the one key every registered system trusts)
     * with the given values, encrypting private_key/passphrase the same way the initial
     * DBInitServlet-generated key is. Takes effect immediately - callers like
     * SSHUtil.authAndAddPubKey() read this table fresh on every connection, nothing is
     * cached, so no restart is needed. Callers must validate the keypair actually loads
     * (see SSHUtil.validateKeyPair) before calling this - an unvalidated bad paste here
     * would break every future SSH connection until fixed.
     *
     * @param con DB connection
     */
    public static void updateApplicationKey(Connection con, String publicKey, String privateKey, String passphrase)
            throws SQLException, GeneralSecurityException {

        try (PreparedStatement delStmt = con.prepareStatement("delete from application_key")) {
            delStmt.execute();
        }

        try (PreparedStatement insStmt = con.prepareStatement(
                "insert into application_key (public_key, private_key, passphrase) values(?,?,?)")) {
            insStmt.setString(1, publicKey);
            insStmt.setString(2, EncryptionUtil.encrypt(privateKey));
            insStmt.setString(3, EncryptionUtil.encrypt(passphrase == null ? "" : passphrase));
            insStmt.execute();
        }
    }
}
