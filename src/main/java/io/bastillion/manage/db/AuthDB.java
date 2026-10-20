/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.User;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.EncryptionUtil;
import io.bastillion.manage.util.ExternalAuthException;
import io.bastillion.manage.util.ExternalAuthUtil;
import org.apache.commons.lang3.StringUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

/**
 * DAO to login administrative users
 */
public class AuthDB {

    public static final int EXPIRATION_DAYS = StringUtils.isNumeric(AppConfig.getProperty("accountExpirationDays")) ? Integer.parseInt(AppConfig.getProperty("accountExpirationDays")) : -1;

    private AuthDB() {
    }

    /**
     * auth user and return auth token if valid auth
     *
     * @param auth username and password object
     * @return auth token if success
     * @throws ExternalAuthException if the directory could not be asked and no local account
     *                               matched either
     */
    public static String login(Auth auth) throws SQLException, GeneralSecurityException, ExternalAuthException {
        //check ldap first - if the directory is down, a local account (a break-glass admin)
        //can still sign in, and only then is the outage reported
        String authToken = null;
        ExternalAuthException externalAuthError = null;
        try {
            authToken = ExternalAuthUtil.login(auth);
        } catch (ExternalAuthException ex) {
            externalAuthError = ex;
        }

        if (StringUtils.isEmpty(authToken)) {

            try (Connection con = DBUtils.getConn();
                 //login
                 PreparedStatement stmt = con.prepareStatement("select * from users where username=?")) {
                stmt.setString(1, auth.getUsername());
                try (ResultSet rs = stmt.executeQuery()) {

                    if (rs.next() && EncryptionUtil.verifyHash(auth.getPassword(), rs.getString("salt"), rs.getString("password"))) {

                        auth.setId(rs.getLong("id"));
                        authToken = UUID.randomUUID().toString();
                        auth.setAuthToken(authToken);
                        auth.setAuthType(Auth.AUTH_BASIC);
                        updateLogin(con, auth);

                    }
                }
            }
        }

        if (authToken == null && externalAuthError != null) {
            throw externalAuthError;
        }
        return authToken;
    }


    /**
     * checks to see if user is an admin based on auth token
     *
     * @param userId    user id
     * @param authToken auth token string
     * @return user type if authorized, null if not authorized
     */
    public static String isAuthorized(Long userId, String authToken) throws SQLException, GeneralSecurityException {

        String authorized = null;

        if (authToken != null && !authToken.trim().equals("")) {

            try (Connection con = DBUtils.getConn();
                 PreparedStatement stmt = con.prepareStatement("select * from users where id=? and auth_token=?")) {
                stmt.setLong(1, userId);
                stmt.setString(2, authToken);
                try (ResultSet rs = stmt.executeQuery()) {

                    if (rs.next()) {
                        authorized = rs.getString("user_type");

                    }
                }
            }
        }
        return authorized;
    }

    /**
     * updates the admin table based on auth id
     *
     * @param con  DB connection
     * @param auth username and password object
     */
    public static void updateLogin(Connection con, Auth auth) throws SQLException, GeneralSecurityException {

        try (PreparedStatement stmt = con.prepareStatement("update users set username=?, auth_type=?, auth_token=?, password=?, salt=? where id=?")) {
            stmt.setString(1, auth.getUsername());
            stmt.setString(2, auth.getAuthType());
            stmt.setString(3, auth.getAuthToken());
            if (StringUtils.isNotEmpty(auth.getPassword())) {
                String salt = EncryptionUtil.generateSalt();
                stmt.setString(4, EncryptionUtil.hashV2(auth.getPassword(), salt));
                stmt.setString(5, salt);
            } else {
                stmt.setString(4, null);
                stmt.setString(5, null);
            }
            stmt.setLong(6, auth.getId());
            stmt.execute();
        }
    }

    /**
     * updates the last login and expiration time
     *
     * @param con  DB connection
     * @param auth username and password object
     */
    public static void updateLastLogin(Connection con, Auth auth) throws SQLException {

        try (PreparedStatement stmt = con.prepareStatement("update users set last_login_tm=?, expiration_tm=? where id=?")) {

            Calendar c = Calendar.getInstance();
            c.setTime(new Date());
            stmt.setTimestamp(1, new Timestamp(c.getTime().getTime()));
            if (Auth.MANAGER.equals(auth.getUserType()) || EXPIRATION_DAYS <= 0) {
                stmt.setTimestamp(2, null);
            } else {
                c.add(Calendar.DATE, EXPIRATION_DAYS);
                stmt.setTimestamp(2, new Timestamp(c.getTime().getTime()));
            }
            stmt.setLong(3, auth.getId());
            stmt.execute();
        }
    }

    /**
     * updates the last login and expiration time
     *
     * @param auth username and password object
     */
    public static void updateLastLogin(Auth auth) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn()) {
            updateLastLogin(con, auth);
        }
    }

    /**
     * updates password for admin using auth token
     */
    public static boolean updatePassword(Auth auth) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return updatePassword(con, auth);
        }
    }

    /**
     * updates password for admin using auth token
     *
     * @param con DB connection
     */
    public static boolean updatePassword(Connection con, Auth auth) throws SQLException, GeneralSecurityException {
        boolean success = false;

        try (PreparedStatement stmt = con.prepareStatement("select * from users where auth_token=?")) {
            stmt.setString(1, auth.getAuthToken());
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next() && EncryptionUtil.verifyHash(auth.getPrevPassword(), rs.getString("salt"), rs.getString("password"))) {

                    String salt = EncryptionUtil.generateSalt();
                    try (PreparedStatement updateStmt = con.prepareStatement("update users set password=?, salt=? where auth_token=?")) {
                        updateStmt.setString(1, EncryptionUtil.hashV2(auth.getPassword(), salt));
                        updateStmt.setString(2, salt);
                        updateStmt.setString(3, auth.getAuthToken());
                        updateStmt.execute();
                    }
                    success = true;
                }
            }
        }

        return success;
    }

    /**
     * returns user id based on auth token
     *
     * @param authToken auth token
     * @param con       DB connection
     * @return user
     */
    public static User getUserByAuthToken(Connection con, String authToken) throws SQLException {

        User user = null;
        try (PreparedStatement stmt = con.prepareStatement("select * from users where auth_token=?")) {
            stmt.setString(1, authToken);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Long userId = rs.getLong("id");
                    user = UserDB.getUser(con, userId);
                    user.setUiTheme(UserThemeDB.getUiTheme(con, userId));
                }
            }
        }

        return user;
    }

    /**
     * returns user based on auth token
     *
     * @param authToken auth token
     * @return user
     */
    public static User getUserByAuthToken(String authToken) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getUserByAuthToken(con, authToken);
        }
    }

    /**
     * returns the shared secret based on user id
     *
     * @param userId user id
     * @return auth object
     */
    public static String getSharedSecret(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getSharedSecret(con, userId);
        }
    }

    /**
     * returns the shared secret based on user id
     *
     * @param con    DB connection
     * @param userId user id
     * @return auth object
     */
    public static String getSharedSecret(Connection con, Long userId) throws SQLException, GeneralSecurityException {

        String sharedSecret = null;
        try (PreparedStatement stmt = con.prepareStatement("select * from users where id=?")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    sharedSecret = EncryptionUtil.decrypt(rs.getString("otp_secret"));
                }
            }
        }

        return sharedSecret;
    }

    /**
     * updates shared secret based on auth token
     *
     * @param secret    OTP shared secret
     * @param authToken auth token
     */
    public static void updateSharedSecret(String secret, String authToken) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            updateSharedSecret(con, secret, authToken);
        }
    }

    /**
     * updates shared secret based on auth token
     *
     * @param con       DB connection
     * @param secret    OTP shared secret
     * @param authToken auth token
     */
    public static void updateSharedSecret(Connection con, String secret, String authToken) throws SQLException, GeneralSecurityException {

        try (PreparedStatement stmt = con.prepareStatement("update users set otp_secret=? where auth_token=?")) {
            stmt.setString(1, EncryptionUtil.encrypt(secret));
            stmt.setString(2, authToken);
            stmt.execute();
        }
    }


    /**
     * returns user base on username
     *
     * Exact (case-insensitive) match only - uid comes from an external identity (SAML NameID
     * or LDAP login name), so it must never be treated as a LIKE pattern where % or _ would
     * match some other account.
     *
     * @param con DB connection
     * @param uid username id
     * @return user object
     */
    public static User getUserByUID(Connection con, String uid) throws SQLException {

        User user = null;
        try (PreparedStatement stmt = con.prepareStatement("select * from users where lower(username) = lower(?)")) {
            stmt.setString(1, uid);
            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    //usernames differing only by case are ambiguous - refuse rather than
                    //silently pick one of the accounts
                    if (user != null) {
                        throw new SQLException("Multiple users match username " + uid);
                    }
                    user = UserDB.mapUser(rs);
                    user.setProfileList(UserProfileDB.getProfilesByUser(con, user.getId()));
                }
            }
        }

        return user;
    }
}
