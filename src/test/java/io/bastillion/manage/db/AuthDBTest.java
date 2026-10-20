/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.User;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.EncryptionUtil;
import io.bastillion.manage.util.ExternalAuthException;
import io.bastillion.manage.util.ExternalAuthUtil;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

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

    // --- login() when the directory cannot be asked ---

    private Auth credentials(String username, String password) {
        Auth auth = new Auth();
        auth.setUsername(username);
        auth.setPassword(password);
        return auth;
    }

    @Test
    void directoryOutageStillLetsALocalAccountIn() throws Exception {
        Connection con = DbTestSupport.newConnection();
        String salt = EncryptionUtil.generateSalt();
        try (PreparedStatement stmt = con.prepareStatement("insert into users(username, password, salt, user_type) values ('breakglass', ?, ?, 'M')")) {
            stmt.setString(1, EncryptionUtil.hashV2("local-pw", salt));
            stmt.setString(2, salt);
            stmt.execute();
        }

        try (MockedStatic<ExternalAuthUtil> external = mockStatic(ExternalAuthUtil.class);
             MockedStatic<DBUtils> dbUtils = mockStatic(DBUtils.class)) {
            external.when(() -> ExternalAuthUtil.login(any())).thenThrow(new ExternalAuthException("could not connect to the directory"));
            dbUtils.when(DBUtils::getConn).thenReturn(con);

            assertNotNull(AuthDB.login(credentials("breakglass", "local-pw")));
        }
    }

    @Test
    void directoryOutageIsReportedWhenNoLocalAccountMatches() throws Exception {
        Connection con = DbTestSupport.newConnection();

        try (MockedStatic<ExternalAuthUtil> external = mockStatic(ExternalAuthUtil.class);
             MockedStatic<DBUtils> dbUtils = mockStatic(DBUtils.class)) {
            external.when(() -> ExternalAuthUtil.login(any())).thenThrow(new ExternalAuthException("could not connect to the directory"));
            dbUtils.when(DBUtils::getConn).thenReturn(con);

            assertThrows(ExternalAuthException.class, () -> AuthDB.login(credentials("jdoe", "directory-pw")));
        }
    }
}
