/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.model.User;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.EncryptionUtil;
import org.apache.commons.lang3.StringUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Set;
import java.util.Calendar;
import java.util.Date;

import static io.bastillion.manage.db.AuthDB.EXPIRATION_DAYS;


/**
 * DAO class to manage users
 */
public class UserDB {

    public static final String PASSWORD = "password";
    public static final String FIRST_NM = "first_nm";
    public static final String LAST_NM = "last_nm";
    public static final String EMAIL = "email";
    public static final String USERNAME = "username";
    public static final String USER_TYPE = "user_type";
    public static final String AUTH_TYPE = "auth_type";
    public static final String PROFILE_ID = "profile_id";
    public static final String LAST_LOGIN_TM = "last_login_tm";
    public static final String EXPIRATION_TM = "expiration_tm";
    /**
     * Columns the user list may be ordered by - see {@link SortedSet#toOrderByClause(Set)}.
     * Mirrors the sortable headers in manage/view_users.html. Note what is deliberately
     * absent: PASSWORD (and the salt and otp_secret columns, which have no constant here).
     * Ordering by a credential column reveals the relative order of every stored value.
     */
    private static final Set<String> SORTABLE_FIELDS = Set.of(
            FIRST_NM, LAST_NM, EMAIL, USERNAME, USER_TYPE, AUTH_TYPE, LAST_LOGIN_TM, EXPIRATION_TM);

    private UserDB() {
    }

    /**
     * returns users based on sort order defined
     *
     * @param sortedSet object that defines sort order
     * @return sorted user list
     */
    public static SortedSet getUserSet(SortedSet sortedSet) throws SQLException, GeneralSecurityException {

        ArrayList<User> userList = new ArrayList<>();

        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);
        String sql = "select * from  users" + orderBy;

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                User user = new User();
                user.setId(rs.getLong("id"));
                user.setFirstNm(rs.getString(FIRST_NM));
                user.setLastNm(rs.getString(LAST_NM));
                user.setEmail(rs.getString(EMAIL));
                user.setUsername(rs.getString(USERNAME));
                user.setPassword(rs.getString(PASSWORD));
                user.setAuthType(rs.getString(AUTH_TYPE));
                user.setUserType(rs.getString(USER_TYPE));
                user.setLastLoginTm(rs.getTimestamp(LAST_LOGIN_TM));
                user.setExpirationTm(rs.getTimestamp(EXPIRATION_TM));
                user.setExpired(EXPIRATION_DAYS > 0 && user.getExpirationTm() != null && user.getExpirationTm().before(new Date()));
                userList.add(user);

            }
        }

        sortedSet.setItemList(userList);
        return sortedSet;
    }

    /**
     * returns all admin users based on sort order defined
     *
     * @param sortedSet object that defines sort order
     * @return sorted user list
     * @profileId check if user is apart of given profile
     */
    public static SortedSet getAdminUserSet(SortedSet sortedSet, Long profileId) throws SQLException, GeneralSecurityException {

        ArrayList<User> userList = new ArrayList<>();


        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);
        String sql = "select u.*, m.profile_id from users u left join user_map  m on m.user_id = u.id and m.profile_id = ? where u.user_type like '" + User.ADMINISTRATOR + "'" + orderBy;

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql)) {
            stmt.setLong(1, profileId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    User user = new User();
                    user.setId(rs.getLong("id"));
                    user.setFirstNm(rs.getString(FIRST_NM));
                    user.setLastNm(rs.getString(LAST_NM));
                    user.setEmail(rs.getString(EMAIL));
                    user.setUsername(rs.getString(USERNAME));
                    user.setPassword(rs.getString(PASSWORD));
                    user.setAuthType(rs.getString(AUTH_TYPE));
                    user.setUserType(rs.getString(USER_TYPE));
                    user.setLastLoginTm(rs.getTimestamp(LAST_LOGIN_TM));
                    user.setExpirationTm(rs.getTimestamp(EXPIRATION_TM));
                    user.setExpired(EXPIRATION_DAYS > 0 && user.getExpirationTm() != null && user.getExpirationTm().before(new Date()));
                    user.setChecked(profileId.equals(rs.getLong(PROFILE_ID)));
                    userList.add(user);

                }
            }
        }

        sortedSet.setItemList(userList);
        return sortedSet;
    }


    /**
     * returns user base on id
     *
     * @param userId user id
     * @return user object
     */
    public static User getUser(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getUser(con, userId);
        }
    }

    /**
     * returns user base on id
     *
     * @param con    DB connection
     * @param userId user id
     * @return user object
     */
    public static User getUser(Connection con, Long userId) throws SQLException {

        User user = null;
        try (PreparedStatement stmt = con.prepareStatement("select * from  users where id=?")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    user = new User();
                    user.setId(rs.getLong("id"));
                    user.setFirstNm(rs.getString(FIRST_NM));
                    user.setLastNm(rs.getString(LAST_NM));
                    user.setEmail(rs.getString(EMAIL));
                    user.setUsername(rs.getString(USERNAME));
                    user.setPassword(rs.getString(PASSWORD));
                    user.setAuthType(rs.getString(AUTH_TYPE));
                    user.setUserType(rs.getString(USER_TYPE));
                    user.setLastLoginTm(rs.getTimestamp(LAST_LOGIN_TM));
                    user.setExpirationTm(rs.getTimestamp(EXPIRATION_TM));
                    user.setExpired(EXPIRATION_DAYS > 0 && user.getExpirationTm() != null && user.getExpirationTm().before(new Date()));
                    user.setSalt(rs.getString("salt"));
                    user.setProfileList(UserProfileDB.getProfilesByUser(con, userId));
                }
            }
        }

        return user;
    }

    /**
     * inserts new user
     *
     * @param user user object
     */
    public static Long insertUser(User user) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return insertUser(con, user);
        }
    }

    /**
     * inserts new user
     *
     * @param con  DB connection
     * @param user user object
     */
    public static Long insertUser(Connection con, User user) throws SQLException, GeneralSecurityException {

        Long userId = null;

        try (PreparedStatement stmt = con.prepareStatement("insert into users (first_nm, last_nm, email, username, auth_type, user_type, password, salt, expiration_tm) values (?,?,?,?,?,?,?,?,?)", Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, user.getFirstNm());
            stmt.setString(2, user.getLastNm());
            stmt.setString(3, user.getEmail());
            stmt.setString(4, user.getUsername());
            stmt.setString(5, user.getAuthType());
            stmt.setString(6, user.getUserType());
            if (StringUtils.isNotEmpty(user.getPassword())) {
                String salt = EncryptionUtil.generateSalt();
                stmt.setString(7, EncryptionUtil.hashV2(user.getPassword(), salt));
                stmt.setString(8, salt);
            } else {
                stmt.setString(7, null);
                stmt.setString(8, null);
            }
            if (Auth.MANAGER.equals(user.getUserType()) || EXPIRATION_DAYS <= 0) {
                stmt.setTimestamp(9, null);
            } else {
                Calendar c = Calendar.getInstance();
                c.setTime(new Date());
                c.add(Calendar.DATE, EXPIRATION_DAYS);
                stmt.setTimestamp(9, new Timestamp(c.getTime().getTime()));
            }
            stmt.execute();
            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs != null && rs.next()) {
                    userId = rs.getLong(1);
                }
            }
        }

        return userId;
    }

    /**
     * updates existing user
     *
     * @param user user object
     */
    public static void updateUserNoCredentials(User user) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            try (PreparedStatement stmt = con.prepareStatement("update users set first_nm=?, last_nm=?, email=?, username=?, user_type=? where id=?")) {
                stmt.setString(1, user.getFirstNm());
                stmt.setString(2, user.getLastNm());
                stmt.setString(3, user.getEmail());
                stmt.setString(4, user.getUsername());
                stmt.setString(5, user.getUserType());
                stmt.setLong(6, user.getId());
                stmt.execute();
            }
            if (User.ADMINISTRATOR.equals(user.getUserType())) {
                PublicKeyDB.deleteUnassignedKeysByUser(con, user.getId());
            }
        }
    }

    /**
     * updates existing user
     *
     * @param user user object
     */
    public static void updateUserCredentials(User user) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            String salt = EncryptionUtil.generateSalt();
            try (PreparedStatement stmt = con.prepareStatement("update users set first_nm=?, last_nm=?, email=?, username=?, user_type=?, password=?, salt=? where id=?")) {
                stmt.setString(1, user.getFirstNm());
                stmt.setString(2, user.getLastNm());
                stmt.setString(3, user.getEmail());
                stmt.setString(4, user.getUsername());
                stmt.setString(5, user.getUserType());
                stmt.setString(6, EncryptionUtil.hashV2(user.getPassword(), salt));
                stmt.setString(7, salt);
                stmt.setLong(8, user.getId());
                stmt.execute();
            }

            if (User.ADMINISTRATOR.equals(user.getUserType())) {
                PublicKeyDB.deleteUnassignedKeysByUser(con, user.getId());
            }
        }
    }

    /**
     * deletes user
     *
     * @param userId user id
     */
    public static void deleteUser(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("delete from users where id=?")) {
            stmt.setLong(1, userId);
            stmt.execute();
        }
    }

    /**
     * resets shared secret for user
     *
     * @param userId user id
     */
    public static void resetSharedSecret(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("update users set otp_secret=null where id=?")) {
            stmt.setLong(1, userId);
            stmt.execute();
        }
    }

    /**
     * checks to see if username is unique while ignoring current user
     *
     * @param userId   user id
     * @param username username
     * @return true false indicator
     */
    public static boolean isUnique(Long userId, String username) throws SQLException, GeneralSecurityException {

        boolean isUnique = true;
        if (userId == null) {
            userId = -99L;
        }

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("select * from users where lower(username) like lower(?) and id != ?")) {
            stmt.setString(1, username);
            stmt.setLong(2, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    isUnique = false;
                }
            }
        }

        return isUnique;
    }

    /**
     * Unlock account that has expired due to inactivity.
     *
     * @param userId user Id
     */
    public static void unlockAccount(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("update users set expiration_tm=? where id=?")) {
            Calendar c = Calendar.getInstance();
            c.setTime(new Date());
            c.add(Calendar.DATE, EXPIRATION_DAYS);
            stmt.setTimestamp(1, new Timestamp(c.getTime().getTime()));
            stmt.setLong(2, userId);
            stmt.execute();
        }
    }


}
