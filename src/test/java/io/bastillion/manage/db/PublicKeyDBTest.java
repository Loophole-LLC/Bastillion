/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.util.AuthorizedKeysUtil;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * getPublicKeysForSystem is the query AuthorizedKeysUtil.addPubKey relies on to decide exactly which
 * keys get written into a host's authorized_keys file - get it wrong and either a host is
 * locked out (a key that should be there is missing) or a key leaks onto a system it was
 * never scoped to (present when it shouldn't be).
 */
class PublicKeyDBTest {

    private long insertUser(Connection con, String username) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into users(username) values (?)", java.sql.Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, username);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private long insertSystem(Connection con, String displayNm) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into system(display_nm, username, host, port, authorized_keys) values (?, 'root', 'host', 22, '~/.ssh/authorized_keys')",
                java.sql.Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, displayNm);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private long insertProfile(Connection con, String nm) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into profiles(nm, desc) values (?, '')", java.sql.Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, nm);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private void mapSystemToProfile(Connection con, long profileId, long systemId) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into system_map(profile_id, system_id) values (?, ?)")) {
            stmt.setLong(1, profileId);
            stmt.setLong(2, systemId);
            stmt.execute();
        }
    }

    private void insertKey(Connection con, long userId, Long profileId, String keyNm, boolean enabled) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into public_keys(key_nm, public_key, user_id, profile_id, enabled) values (?, 'ssh-ed25519 AAAA test', ?, ?, ?)")) {
            stmt.setString(1, keyNm);
            stmt.setLong(2, userId);
            if (profileId == null) {
                stmt.setNull(3, Types.NULL);
            } else {
                stmt.setLong(3, profileId);
            }
            stmt.setBoolean(4, enabled);
            stmt.execute();
        }
    }

    @Test
    void globalKeyWithNullProfileAppliesToEverySystem() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long systemId = insertSystem(con, "web-1");
            insertKey(con, userId, null, "global-key", true);

            List<String> keys = PublicKeyDB.getPublicKeysForSystem(con, systemId);

            assertEquals(1, keys.size());
        }
    }

    @Test
    void profileScopedKeyOnlyAppliesToSystemsInThatProfile() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long profileId = insertProfile(con, "prod");
            long inProfile = insertSystem(con, "prod-1");
            long outsideProfile = insertSystem(con, "staging-1");
            mapSystemToProfile(con, profileId, inProfile);
            insertKey(con, userId, profileId, "prod-key", true);

            assertEquals(1, PublicKeyDB.getPublicKeysForSystem(con, inProfile).size());
            assertTrue(PublicKeyDB.getPublicKeysForSystem(con, outsideProfile).isEmpty());
        }
    }

    @Test
    void disabledKeyIsNeverReturnedEvenIfGlobal() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long systemId = insertSystem(con, "web-1");
            insertKey(con, userId, null, "disabled-global-key", false);

            assertTrue(PublicKeyDB.getPublicKeysForSystem(con, systemId).isEmpty());
        }
    }

    @Test
    void nullSystemIdStillReturnsGlobalKeysButNotProfileScopedKeys() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long profileId = insertProfile(con, "prod");
            insertKey(con, userId, null, "global-key", true);
            insertKey(con, userId, profileId, "prod-key", true);

            List<String> keys = PublicKeyDB.getPublicKeysForSystem(con, null);

            assertEquals(1, keys.size());
        }
    }

    @Test
    void getPublicKeyByIdReturnsNullWhenNotFound() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            assertNull(PublicKeyDB.getPublicKey(con, 999L));
        }
    }

    @Test
    void deleteUnassignedKeysByUserKeepsOnlyKeysScopedToTheUsersCurrentProfiles() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long assignedProfile = insertProfile(con, "assigned");
            long unassignedProfile = insertProfile(con, "unassigned");

            // user is only linked (via user_map) to "assigned"
            try (PreparedStatement stmt = con.prepareStatement("insert into user_map(user_id, profile_id) values (?, ?)")) {
                stmt.setLong(1, userId);
                stmt.setLong(2, assignedProfile);
                stmt.execute();
            }

            insertKey(con, userId, assignedProfile, "kept-key", true);
            insertKey(con, userId, unassignedProfile, "orphaned-key", true);
            // A key with no profile_id at all is "unassigned" by this method's own
            // definition (profile_id is null OR not in the user's current profiles) - it
            // is deleted right alongside a key scoped to a profile the user has since
            // lost. This is the opposite of getPublicKeysForSystem's "null profile_id
            // means push everywhere" reading of the same column - worth flagging if that
            // divergence wasn't intentional.
            insertKey(con, userId, null, "unscoped-key", true);

            PublicKeyDB.deleteUnassignedKeysByUser(con, userId);

            List<String> remainingNames = new java.util.ArrayList<>();
            try (var stmt = con.createStatement();
                 var rs = stmt.executeQuery("select key_nm from public_keys order by key_nm")) {
                while (rs.next()) {
                    remainingNames.add(rs.getString(1));
                }
            }
            assertEquals(List.of("kept-key"), remainingNames);
        }
    }
}
