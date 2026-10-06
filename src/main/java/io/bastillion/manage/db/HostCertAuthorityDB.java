/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.HostCertAuthority;
import io.bastillion.manage.util.DBUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * DAO for the host certificate authorities Bastillion trusts.
 * <p>
 * Read on every connection that presents a host certificate, via
 * {@code HostKeyVerifier.getHostKey()}, which is where JSch collects trusted CAs from.
 */
public class HostCertAuthorityDB {

    private HostCertAuthorityDB() {
    }

    public static List<HostCertAuthority> getHostCertAuthorities() throws SQLException, GeneralSecurityException {
        List<HostCertAuthority> authorities = new ArrayList<>();
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "select * from host_cert_authority order by create_tm asc");
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                HostCertAuthority ca = new HostCertAuthority();
                ca.setId(rs.getLong("id"));
                ca.setPublicKey(rs.getString("public_key"));
                ca.setFingerprint(rs.getString("fingerprint"));
                ca.setComment(rs.getString("comment"));
                ca.setCreateTm(rs.getTimestamp("create_tm"));
                authorities.add(ca);
            }
        }
        return authorities;
    }

    public static void insertHostCertAuthority(String publicKey, String fingerprint, String comment)
            throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "insert into host_cert_authority (public_key, fingerprint, comment) values (?,?,?)")) {
            stmt.setString(1, publicKey);
            stmt.setString(2, fingerprint);
            stmt.setString(3, comment);
            stmt.executeUpdate();
        }
    }

    public static void deleteHostCertAuthority(Long id) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("delete from host_cert_authority where id=?")) {
            stmt.setLong(1, id);
            stmt.executeUpdate();
        }
    }

    public static boolean exists(String fingerprint) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "select 1 from host_cert_authority where fingerprint=?")) {
            stmt.setString(1, fingerprint);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }
}
