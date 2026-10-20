/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.manage.db.DbTestSupport;
import io.bastillion.manage.db.UserProfileDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.User;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * link() decides which local account an LDAP or SAML login becomes, then hands that account
 * a fresh auth token - matching the wrong row, or linking where policy says not to, gives
 * the login someone else's account.
 */
class ExternalAccountUtilTest {

    private long insertUser(Connection con, String username, String authType, String password) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into users(username, auth_type, password, salt, user_type) values (?, ?, ?, 'salt', 'M')",
                Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, username);
            stmt.setString(2, authType);
            stmt.setString(3, password);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private long insertProfile(Connection con, String nm) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into profiles(nm, desc) values (?, '')", Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, nm);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    private String column(Connection con, long userId, String column) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement("select " + column + " from users where id=?")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                rs.next();
                return rs.getString(1);
            }
        }
    }

    private int userCount(Connection con) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement("select count(*) from users");
             ResultSet rs = stmt.executeQuery()) {
            rs.next();
            return rs.getInt(1);
        }
    }

    private User identity(String username) {
        User user = new User();
        user.setUsername(username);
        return user;
    }

    @Test
    void newIdentityGetsAnExternalAdministratorAccount() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            User newUser = identity("jdoe@corp.com");
            newUser.setFirstNm("Jane");
            newUser.setEmail("jdoe@corp.com");

            String token = ExternalAccountUtil.link(con, newUser, Auth.AUTH_SAML, null, null, null, true);

            assertNotNull(token);
            assertEquals(token, column(con, newUser.getId(), "auth_token"));
            assertEquals(Auth.AUTH_SAML, column(con, newUser.getId(), "auth_type"));
            assertEquals(User.ADMINISTRATOR, column(con, newUser.getId(), "user_type"));
            assertEquals("Jane", column(con, newUser.getId(), "first_nm"));
        }
    }

    @Test
    void existingExternalAccountIsReused() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "jdoe", Auth.AUTH_EXTERNAL, null);

            String token = ExternalAccountUtil.link(con, identity("JDoe"), Auth.AUTH_EXTERNAL, null, null, null, false);

            assertEquals(token, column(con, id, "auth_token"));
            assertEquals(1, userCount(con));
        }
    }

    @Test
    void underscoreIdentityGetsItsOwnAccount() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            long victim = insertUser(con, "john.smith@corp.com", Auth.AUTH_SAML, null);

            ExternalAccountUtil.link(con, identity("john_smith@corp.com"), Auth.AUTH_SAML, null, null, null, true);

            assertNull(column(con, victim, "auth_token"));
            assertEquals(2, userCount(con));
        }
    }

    @Test
    void basicAccountIsLinkedByDefault() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "admin", Auth.AUTH_BASIC, "hash");

            String token = ExternalAccountUtil.link(con, identity("admin"), Auth.AUTH_EXTERNAL, null, null, null, true);

            assertEquals(token, column(con, id, "auth_token"));
            assertEquals(Auth.AUTH_EXTERNAL, column(con, id, "auth_type"));
            assertNull(column(con, id, "password"));
        }
    }

    @Test
    void basicAccountIsRefusedWhenLinkingIsOff() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "admin", Auth.AUTH_BASIC, "hash");

            String token = ExternalAccountUtil.link(con, identity("admin"), Auth.AUTH_SAML, null, null, null, false);

            assertNull(token);
            assertNull(column(con, id, "auth_token"));
            assertEquals(Auth.AUTH_BASIC, column(con, id, "auth_type"));
            assertEquals("hash", column(con, id, "password"));
        }
    }

    @Test
    void rolesAndDefaultProfileSetMembership() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "jdoe", Auth.AUTH_EXTERNAL, null);
            long web = insertProfile(con, "web");
            long db = insertProfile(con, "db");
            long everyone = insertProfile(con, "everyone");
            con.createStatement().execute("insert into user_map(user_id, profile_id) values (" + id + ", " + db + ")");

            ExternalAccountUtil.link(con, identity("jdoe"), Auth.AUTH_EXTERNAL,
                    List.of("web", "db"), List.of("web"), "everyone", true);

            assertTrue(UserProfileDB.checkIsUsersProfile(con, id, web));
            assertFalse(UserProfileDB.checkIsUsersProfile(con, id, db));
            assertTrue(UserProfileDB.checkIsUsersProfile(con, id, everyone));
        }
    }

    @Test
    void nullProfileListLeavesMembershipAlone() throws SQLException, GeneralSecurityException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "jdoe", Auth.AUTH_EXTERNAL, null);
            long db = insertProfile(con, "db");
            con.createStatement().execute("insert into user_map(user_id, profile_id) values (" + id + ", " + db + ")");

            ExternalAccountUtil.link(con, identity("jdoe"), Auth.AUTH_EXTERNAL, null, null, null, true);

            assertTrue(UserProfileDB.checkIsUsersProfile(con, id, db));
        }
    }
}
