/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.KnownHostKey;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.util.DBUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * DAO for the SSH host keys Bastillion has seen managed systems present.
 * <p>
 * This is Bastillion's known_hosts. Before it existed, every SSH connection was opened with
 * {@code StrictHostKeyChecking=no}, so nothing ever compared the key a host presented
 * against the key it presented last time - and the application key, a user's password and a
 * key passphrase are all handed to whatever answers on that address.
 */
public class HostKeyDB {

    public static final String HOST = "host";
    public static final String SORT_BY_HOST = HOST;
    public static final String TYPE = "type";
    public static final String SORT_BY_TYPE = TYPE;
    public static final String STATUS = "status";
    public static final String SORT_BY_STATUS = STATUS;
    public static final String FIRST_SEEN_TM = "first_seen_tm";
    public static final String SORT_BY_FIRST_SEEN_TM = FIRST_SEEN_TM;

    /**
     * Columns the host key list may be ordered by - see {@link SortedSet#toOrderByClause(Set)}.
     * Mirrors the sortable headers in manage/view_host_keys.html. The key material columns
     * are deliberately absent.
     */
    private static final Set<String> SORTABLE_FIELDS =
            Set.of(SORT_BY_HOST, SORT_BY_TYPE, SORT_BY_STATUS, SORT_BY_FIRST_SEEN_TM);

    private HostKeyDB() {
    }

    /**
     * @return every recorded host key, ordered for the manage screen
     */
    public static SortedSet getHostKeySet(SortedSet sortedSet) throws SQLException, GeneralSecurityException {
        List<KnownHostKey> hostKeyList = new ArrayList<>();

        String sql = "select k.*, u.username as approved_by_username from host_key k"
                + " left join users u on u.id = k.approved_by"
                + sortedSet.toOrderByClause(SORTABLE_FIELDS);

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                hostKeyList.add(mapHostKey(rs));
            }
        }

        sortedSet.setItemList(hostKeyList);
        return sortedSet;
    }

    /**
     * @return the recorded key with this row id, or null if none
     */
    public static KnownHostKey getHostKey(Long id) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "select k.*, u.username as approved_by_username from host_key k"
                             + " left join users u on u.id = k.approved_by where k.id=?")) {
            stmt.setLong(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? mapHostKey(rs) : null;
            }
        }
    }

    /**
     * @return the recorded key for this host, port and key type, or null if none
     */
    public static KnownHostKey getHostKey(String host, int port, String type) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn()) {
            return getHostKey(con, host, port, type);
        }
    }

    private static KnownHostKey getHostKey(Connection con, String host, int port, String type) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "select k.*, u.username as approved_by_username from host_key k"
                        + " left join users u on u.id = k.approved_by"
                        + " where k.host=? and k.port=? and k.type=?")) {
            stmt.setString(1, host);
            stmt.setInt(2, port);
            stmt.setString(3, type);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? mapHostKey(rs) : null;
            }
        }
    }

    /**
     * Records a host key seen for the first time.
     *
     * @param status {@link KnownHostKey#TRUSTED} under accept-new, or
     *               {@link KnownHostKey#PENDING} under strict verification
     */
    public static void insertHostKey(String host, int port, String type, String publicKey,
                                     String fingerprint, String status) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "insert into host_key (host, port, type, public_key, fingerprint, status)"
                             + " values (?,?,?,?,?,?)")) {
            stmt.setString(1, host);
            stmt.setInt(2, port);
            stmt.setString(3, type);
            stmt.setString(4, publicKey);
            stmt.setString(5, fingerprint);
            stmt.setString(6, status);
            stmt.executeUpdate();
        }
    }

    /**
     * Flags a host as presenting a key other than its trusted one, keeping both.
     * <p>
     * The offered key is stored beside the trusted key rather than replacing it: overwriting
     * is what a machine-in-the-middle wants, and a manager needs to see which key they
     * approved and which one turned up in order to tell a re-provisioned host from an attack.
     */
    public static void markChanged(String host, int port, String type,
                                   String offeredPublicKey, String offeredFingerprint) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "update host_key set status=?, offered_public_key=?, offered_fingerprint=?"
                             + " where host=? and port=? and type=?")) {
            stmt.setString(1, KnownHostKey.CHANGED);
            stmt.setString(2, offeredPublicKey);
            stmt.setString(3, offeredFingerprint);
            stmt.setString(4, host);
            stmt.setInt(5, port);
            stmt.setString(6, type);
            stmt.executeUpdate();
        }
    }

    /**
     * Trusts a host key: approves a pending one, or accepts the newly offered key of a
     * changed one as the trusted key from now on.
     *
     * @param id     host key row id
     * @param userId the manager approving it, recorded for the audit trail
     */
    public static void approveHostKey(Long id, Long userId) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "update host_key set"
                             + " public_key = coalesce(offered_public_key, public_key),"
                             + " fingerprint = coalesce(offered_fingerprint, fingerprint),"
                             + " offered_public_key = null, offered_fingerprint = null,"
                             + " status=?, approved_tm=?, approved_by=?"
                             + " where id=?")) {
            stmt.setString(1, KnownHostKey.TRUSTED);
            stmt.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
            if (userId == null) {
                stmt.setNull(3, java.sql.Types.INTEGER);
            } else {
                stmt.setLong(3, userId);
            }
            stmt.setLong(4, id);
            stmt.executeUpdate();
        }
    }

    /**
     * Distrusts a host key without forgetting it, so connections stay refused rather than
     * the host being silently re-trusted on its next connection the way a delete would allow
     * under accept-new.
     */
    public static void revokeHostKey(Long id) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("update host_key set status=? where id=?")) {
            stmt.setString(1, KnownHostKey.REVOKED);
            stmt.setLong(2, id);
            stmt.executeUpdate();
        }
    }

    /**
     * Forgets a host key entirely, so the next connection treats the host as new.
     */
    public static void deleteHostKey(Long id) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("delete from host_key where id=?")) {
            stmt.setLong(1, id);
            stmt.executeUpdate();
        }
    }

    /**
     * @return number of host keys currently refusing connections, for the nav badge
     */
    public static int getBlockingCount() throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(
                     "select count(*) from host_key where status <> ?")) {
            stmt.setString(1, KnownHostKey.TRUSTED);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    private static KnownHostKey mapHostKey(ResultSet rs) throws SQLException {
        KnownHostKey hostKey = new KnownHostKey();
        hostKey.setId(rs.getLong("id"));
        hostKey.setHost(rs.getString(HOST));
        hostKey.setPort(rs.getInt("port"));
        hostKey.setType(rs.getString(TYPE));
        hostKey.setPublicKey(rs.getString("public_key"));
        hostKey.setFingerprint(rs.getString("fingerprint"));
        hostKey.setStatus(rs.getString(STATUS));
        hostKey.setOfferedPublicKey(rs.getString("offered_public_key"));
        hostKey.setOfferedFingerprint(rs.getString("offered_fingerprint"));
        hostKey.setFirstSeenTm(rs.getTimestamp(FIRST_SEEN_TM));
        hostKey.setApprovedTm(rs.getTimestamp("approved_tm"));
        hostKey.setApprovedBy(rs.getString("approved_by_username"));
        return hostKey;
    }
}
