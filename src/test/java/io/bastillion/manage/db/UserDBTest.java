/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.User;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * isUnique decides whether a new or renamed account may take a username - a false "unique"
 * lets two accounts share a name an external login can then match, a false "taken" just
 * blocks a legitimate name. getUser feeds the edit screens, so it should carry no credentials.
 */
class UserDBTest {

    private long insertUser(Connection con, String username) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "insert into users(username, password, salt) values (?, 'hash', 'salt')", Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, username);
            stmt.execute();
            var rs = stmt.getGeneratedKeys();
            rs.next();
            return rs.getLong(1);
        }
    }

    @Test
    void usernameTakenIgnoringCase() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            insertUser(con, "jdoe");

            assertFalse(UserDB.isUnique(con, null, "JDoe"));
        }
    }

    @Test
    void underscoreDoesNotCollideWithOtherNames() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            insertUser(con, "john.smith");

            assertTrue(UserDB.isUnique(con, null, "john_smith"));
        }
    }

    @Test
    void renamingToOwnUsernameIsAllowed() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "jdoe");

            assertTrue(UserDB.isUnique(con, id, "jdoe"));
        }
    }

    @Test
    void loadedUserCarriesNoCredentials() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            long id = insertUser(con, "jdoe");

            User user = UserDB.getUser(con, id);

            assertEquals("jdoe", user.getUsername());
            assertNull(user.getPassword());
            assertNull(user.getSalt());
        }
    }
}
