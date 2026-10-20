/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * assignProfilesToUser turns LDAP/SAML role names into profile membership, and profile
 * membership is what decides which systems a user's key lands on - a role name has to
 * match its own profile and nothing else.
 */
class UserProfileDBTest {

    private long insert(Connection con, String sql, String value) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, value);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    @Test
    void roleMatchesItsOwnProfileIgnoringCase() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insert(con, "insert into users(username) values (?)", "jdoe");
            long profileId = insert(con, "insert into profiles(nm, desc) values (?, '')", "Web_Prod");

            UserProfileDB.assignProfilesToUser(con, userId, List.of("web_prod"), List.of("web_prod"));

            assertTrue(UserProfileDB.checkIsUsersProfile(con, userId, profileId));
        }
    }

    @Test
    void underscoreInRoleDoesNotMatchAnotherProfile() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            long userId = insert(con, "insert into users(username) values (?)", "jdoe");
            long otherProfileId = insert(con, "insert into profiles(nm, desc) values (?, '')", "web-prod");

            UserProfileDB.assignProfilesToUser(con, userId, List.of("web_prod"), List.of("web_prod"));

            assertFalse(UserProfileDB.checkIsUsersProfile(con, userId, otherProfileId));
        }
    }
}
