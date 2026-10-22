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
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    private static String realKey() throws Exception {
        com.jcraft.jsch.KeyPair kp = com.jcraft.jsch.KeyPair.genKeyPair(new com.jcraft.jsch.JSch(), com.jcraft.jsch.KeyPair.ED25519);
        return "ssh-ed25519 " + java.util.Base64.getEncoder().encodeToString(kp.getPublicKeyBlob()) + " alice@laptop";
    }

    private long insertRealKey(Connection con, long userId, Long profileId, String publicKey) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into public_keys(key_nm, public_key, fingerprint, user_id, profile_id) values ('k', ?, ?, ?, ?)",
                java.sql.Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, publicKey);
            stmt.setString(2, publicKey == null ? null : io.bastillion.manage.util.OpenSSHKeyUtil.getFingerprint(publicKey));
            stmt.setLong(3, userId);
            if (profileId == null) {
                stmt.setNull(4, Types.NULL);
            } else {
                stmt.setLong(4, profileId);
            }
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private static io.bastillion.manage.model.PublicKey key(Long id, Long profileId, String publicKey) {
        io.bastillion.manage.model.PublicKey key = new io.bastillion.manage.model.PublicKey();
        key.setId(id);
        key.setPublicKey(publicKey);
        if (profileId != null) {
            io.bastillion.manage.model.Profile profile = new io.bastillion.manage.model.Profile();
            profile.setId(profileId);
            key.setProfile(profile);
        }
        return key;
    }

    @Test
    void aNewKeyIsADuplicateOfTheSameKeyUnderTheSameProfileOrUnderNone() throws Exception {
        // "profile_id = ? and id <> ?" with nulls bound matched nothing, so a new key - no id
        // yet - was never a duplicate, and neither was any key registered for all systems
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long profileId = insertProfile(con, "prod");
            String pub = realKey();
            insertRealKey(con, userId, profileId, pub);
            insertRealKey(con, userId, null, pub);

            assertTrue(PublicKeyDB.isKeyRegistered(con, userId, key(null, profileId, pub)));
            assertTrue(PublicKeyDB.isKeyRegistered(con, userId, key(null, null, pub)));
        }
    }

    @Test
    void theSameKeyUnderAnotherProfileOrAnotherUserIsNotADuplicate() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long alice = insertUser(con, "alice");
            long bob = insertUser(con, "bob");
            long prod = insertProfile(con, "prod");
            long staging = insertProfile(con, "staging");
            String pub = realKey();
            insertRealKey(con, alice, prod, pub);

            assertFalse(PublicKeyDB.isKeyRegistered(con, alice, key(null, staging, pub)));
            assertFalse(PublicKeyDB.isKeyRegistered(con, alice, key(null, null, pub)));
            assertFalse(PublicKeyDB.isKeyRegistered(con, bob, key(null, prod, pub)));
        }
    }

    @Test
    void editingAKeyDoesNotMakeItADuplicateOfItself() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long profileId = insertProfile(con, "prod");
            String pub = realKey();
            long id = insertRealKey(con, userId, profileId, pub);

            assertFalse(PublicKeyDB.isKeyRegistered(con, userId, key(id, profileId, pub)));
        }
    }

    @Test
    void disablingAKeyTakesEveryRecordOfItOffEverySystemAndEnablingPutsThemBack() throws Exception {
        // the confirmation promises the key "is removed from every system" - disabling only the
        // record clicked left any other record of the same key pushing it to its systems
        try (Connection con = DbTestSupport.newConnection()) {
            long alice = insertUser(con, "alice");
            long bob = insertUser(con, "bob");
            long prod = insertProfile(con, "prod");
            long staging = insertProfile(con, "staging");
            long prodSystem = insertSystem(con, "prod-1");
            long stagingSystem = insertSystem(con, "staging-1");
            mapSystemToProfile(con, prod, prodSystem);
            mapSystemToProfile(con, staging, stagingSystem);
            String pub = realKey();
            String other = realKey();
            long clicked = insertRealKey(con, alice, prod, pub);
            insertRealKey(con, alice, staging, pub);
            insertRealKey(con, bob, null, pub);
            insertRealKey(con, bob, null, other);

            PublicKeyDB.disableKey(con, clicked);

            assertEquals(List.of(other), PublicKeyDB.getPublicKeysForSystem(con, prodSystem));
            assertEquals(List.of(other), PublicKeyDB.getPublicKeysForSystem(con, stagingSystem));
            assertTrue(PublicKeyDB.isKeyDisabled(con, io.bastillion.manage.util.OpenSSHKeyUtil.getFingerprint(pub)));

            PublicKeyDB.enableKey(con, clicked);

            assertEquals(3, PublicKeyDB.getPublicKeysForSystem(con, prodSystem).size());
            assertEquals(3, PublicKeyDB.getPublicKeysForSystem(con, stagingSystem).size());
        }
    }

    @Test
    void disablingAnOlderRecordWithNoFingerprintStillDisablesItAndNothingElse() throws Exception {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insertUser(con, "alice");
            long systemId = insertSystem(con, "web-1");
            long legacy = insertRealKey(con, userId, null, null);
            String other = realKey();
            insertRealKey(con, userId, null, other);
            try (PreparedStatement stmt = con.prepareStatement("update public_keys set public_key='ssh-ed25519 AAAA legacy' where id=?")) {
                stmt.setLong(1, legacy);
                stmt.execute();
            }

            PublicKeyDB.disableKey(con, legacy);

            assertEquals(List.of(other), PublicKeyDB.getPublicKeysForSystem(con, systemId));
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
