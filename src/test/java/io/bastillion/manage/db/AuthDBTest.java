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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * getUserByUID maps a SAML NameID or LDAP login name onto a local account, and the caller
 * then rotates that account's auth token and hands the session to whoever logged in - so
 * a lookup that matches the wrong row is an account takeover, not just a wrong result.
 */
class AuthDBTest {

    private void insertUser(Connection con, String username, String userType) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement("insert into users(username, user_type) values (?, ?)")) {
            stmt.setString(1, username);
            stmt.setString(2, userType);
            stmt.execute();
        }
    }

    @Test
    void matchesUsernameCaseInsensitively() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            insertUser(con, "jdoe", "A");

            User user = AuthDB.getUserByUID(con, "JDoe");

            assertEquals("jdoe", user.getUsername());
        }
    }

    @Test
    void doesNotTreatPercentAsWildcard() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            insertUser(con, "admin", "M");
            insertUser(con, "jdoe", "A");

            assertNull(AuthDB.getUserByUID(con, "%"));
        }
    }

    @Test
    void doesNotTreatUnderscoreAsWildcard() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            insertUser(con, "admin", "M");
            insertUser(con, "john.smith@corp.com", "A");

            assertNull(AuthDB.getUserByUID(con, "adm_n"));
            assertNull(AuthDB.getUserByUID(con, "john_smith@corp.com"));
        }
    }

    @Test
    void rejectsUsernamesThatDifferOnlyByCase() throws SQLException {
        try (Connection con = DbTestSupport.newConnection()) {
            insertUser(con, "admin", "M");
            insertUser(con, "Admin", "A");

            assertThrows(SQLException.class, () -> AuthDB.getUserByUID(con, "admin"));
        }
    }
}
