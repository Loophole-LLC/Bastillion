/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.Profile;
import io.bastillion.manage.util.DBUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * DAO to manage user profile information
 */
public class UserProfileDB {

    private UserProfileDB() {
    }

    /**
     * sets users for profile
     *
     * @param profileId  profile id
     * @param userIdList list of user ids
     */
    public static void setUsersForProfile(Long profileId, List<Long> userIdList) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            setUsersForProfile(con, profileId, userIdList);
        }
    }

    /**
     * sets users for profile
     *
     * @param con        DB connection
     * @param profileId  profile id
     * @param userIdList list of user ids
     */
    public static void setUsersForProfile(Connection con, Long profileId, List<Long> userIdList) throws SQLException {

        try (PreparedStatement stmt = con.prepareStatement("delete from user_map where profile_id=?")) {
            stmt.setLong(1, profileId);
            stmt.execute();
        }

        for (Long userId : userIdList) {
            try (PreparedStatement stmt = con.prepareStatement("insert into user_map (profile_id, user_id) values (?,?)")) {
                stmt.setLong(1, profileId);
                stmt.setLong(2, userId);
                stmt.execute();
            }
        }
        //delete all unassigned keys by profile
        PublicKeyDB.deleteUnassignedKeysByProfile(con, profileId);
    }

    /**
     * return a list of profiles for user
     *
     * @param userId user id
     * @return profile list
     */
    public static List<Profile> getProfilesByUser(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getProfilesByUser(con, userId);
        }
    }

    /**
     * return a list of profiles for user
     *
     * @param userId user id
     * @return profile list
     */
    public static List<Profile> getProfilesByUser(Connection con, Long userId) throws SQLException {

        ArrayList<Profile> profileList = new ArrayList<>();

        try (PreparedStatement stmt = con.prepareStatement("select * from  profiles g, user_map m where g.id=m.profile_id and m.user_id=? order by nm asc")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    profileList.add(ProfileDB.mapProfile(rs));
                }
            }
        }

        return profileList;
    }

    /**
     * checks to determine if user belongs to profile
     *
     * @param userId    user id
     * @param profileId profile id
     * @return true if user belongs to profile
     */
    public static boolean checkIsUsersProfile(Long userId, Long profileId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return checkIsUsersProfile(con, userId, profileId);
        }
    }

    /**
     * checks to determine if user belongs to profile
     *
     * @param con       DB connection
     * @param userId    user id
     * @param profileId profile id
     * @return true if user belongs to profile
     */
    public static boolean checkIsUsersProfile(Connection con, Long userId, Long profileId) throws SQLException {
        boolean isUsersProfile = false;

        try (PreparedStatement stmt = con.prepareStatement("select * from user_map where profile_id=? and user_id=?")) {
            stmt.setLong(1, profileId);
            stmt.setLong(2, userId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    isUsersProfile = true;
                }
            }
        }

        return isUsersProfile;
    }

    /**
     * assigns profiles to given user
     *
     * @param userId                 user id
     * @param allProfilesNmList      list of all profiles
     * @param assignedProfilesNmList list of assigned profiles
     */
    public static void assignProfilesToUser(Connection con, Long userId, List<String> allProfilesNmList, List<String> assignedProfilesNmList) throws SQLException {

        for (String profileNm : allProfilesNmList) {
            if (StringUtils.isNotEmpty(profileNm)) {

                Long profileId = null;
                try (PreparedStatement stmt = con.prepareStatement("select id from  profiles p where lower(p.nm) = ?")) {
                    stmt.setString(1, profileNm.toLowerCase());
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            profileId = rs.getLong("id");
                        }
                    }
                }

                if (profileId != null) {
                    try (PreparedStatement stmt = con.prepareStatement("delete from user_map where profile_id=? and user_id=?")) {
                        stmt.setLong(1, profileId);
                        stmt.setLong(2, userId);
                        stmt.execute();
                    }

                    if (assignedProfilesNmList.contains(profileNm)) {
                        try (PreparedStatement stmt = con.prepareStatement("insert into user_map (profile_id, user_id) values (?,?)")) {
                            stmt.setLong(1, profileId);
                            stmt.setLong(2, userId);
                            stmt.execute();
                        }
                    }

                    //delete all unassigned keys by profile
                    PublicKeyDB.deleteUnassignedKeysByProfile(con, profileId);
                }

            }
        }

    }

    /**
     * assigns profiles to given user
     *
     * @param userId    user id
     * @param profileNm profile name
     */
    public static void assignProfileToUser(Connection con, Long userId, String profileNm) throws SQLException {

        if (StringUtils.isNotEmpty(profileNm)) {

            Long profileId = null;
            try (PreparedStatement stmt = con.prepareStatement("select id from  profiles p where lower(p.nm) = ?")) {
                stmt.setString(1, profileNm.toLowerCase());
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        profileId = rs.getLong("id");
                    }
                }
            }

            if (profileId != null) {
                try (PreparedStatement stmt = con.prepareStatement("delete from user_map where profile_id=? and user_id=?")) {
                    stmt.setLong(1, profileId);
                    stmt.setLong(2, userId);
                    stmt.execute();
                }

                try (PreparedStatement stmt = con.prepareStatement("insert into user_map (profile_id, user_id) values (?,?)")) {
                    stmt.setLong(1, profileId);
                    stmt.setLong(2, userId);
                    stmt.execute();
                }

                //delete all unassigned keys by profile
                PublicKeyDB.deleteUnassignedKeysByProfile(con, profileId);
            }
        }
    }
}
