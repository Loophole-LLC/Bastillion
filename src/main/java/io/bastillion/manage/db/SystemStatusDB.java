/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.util.DBUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * DAO used to generate a list of public keys and systems associated
 * with them based on system profiles and users assigned to the profiles.
 */
public class SystemStatusDB {

    public static final String STATUS_CD = "status_cd";

    private SystemStatusDB() {
    }

    /**
     * set the initial status for selected systems
     *
     * @param systemSelectIds systems ids to set initial status
     * @param userId          user id
     * @param userType        user type
     */
    public static void setInitialSystemStatus(List<Long> systemSelectIds, Long userId, String userType) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            setInitialSystemStatus(con, systemSelectIds, userId, userType);
        }
    }

    /**
     * set the initial status for selected systems
     *
     * @param con             DB connection
     * @param systemSelectIds systems ids to set initial status
     * @param userId          user id
     * @param userType        user type
     */
    public static void setInitialSystemStatus(Connection con, List<Long> systemSelectIds, Long userId, String userType) throws SQLException {

        //checks perms if to see if in assigned profiles
        if (!Auth.MANAGER.equals(userType)) {
            systemSelectIds = SystemDB.checkSystemPerms(con, systemSelectIds, userId);
        }

        //deletes all old systems
        deleteAllSystemStatus(con, userId);
        for (Long hostSystemId : systemSelectIds) {

            HostSystem hostSystem = new HostSystem();
            hostSystem.setId(hostSystemId);
            hostSystem.setStatusCd(HostSystem.INITIAL_STATUS);

            //insert new status
            insertSystemStatus(con, hostSystem, userId);
        }
    }

    /**
     * deletes all records from status table for user
     *
     * @param con    DB connection object
     * @param userId user id
     */
    private static void deleteAllSystemStatus(Connection con, Long userId) throws SQLException {

        try (PreparedStatement stmt = con.prepareStatement("delete from status where user_id=?")) {
            stmt.setLong(1, userId);
            stmt.execute();
        }
    }


    /**
     * inserts into the status table to keep track of key placement status
     *
     * @param con        DB connection object
     * @param hostSystem systems for authorized_keys replacement
     * @param userId     user id
     */
    private static void insertSystemStatus(Connection con, HostSystem hostSystem, Long userId) throws SQLException {

        try (PreparedStatement stmt = con.prepareStatement("insert into status (id, status_cd, user_id) values (?,?,?)")) {
            stmt.setLong(1, hostSystem.getId());
            stmt.setString(2, hostSystem.getStatusCd());
            stmt.setLong(3, userId);
            stmt.execute();
        }
    }

    /**
     * updates the status table to keep track of key placement status
     *
     * @param hostSystem systems for authorized_keys replacement
     * @param userId     user id
     */
    public static void updateSystemStatus(HostSystem hostSystem, Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            updateSystemStatus(con, hostSystem, userId);
        }
    }


    /**
     * updates the status table to keep track of key placement status
     *
     * @param con        DB connection
     * @param hostSystem systems for authorized_keys replacement
     * @param userId     user id
     */
    public static void updateSystemStatus(Connection con, HostSystem hostSystem, Long userId) throws SQLException {

        try (PreparedStatement stmt = con.prepareStatement("update status set status_cd=? where id=? and user_id=?")) {
            stmt.setString(1, hostSystem.getStatusCd());
            stmt.setLong(2, hostSystem.getId());
            stmt.setLong(3, userId);
            stmt.execute();
        }
    }


    /**
     * returns all key placement statuses
     *
     * @param userId user id
     */
    public static List<HostSystem> getAllSystemStatus(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getAllSystemStatus(con, userId);
        }
    }

    /**
     * returns all key placement statuses
     *
     * @param con    DB connection object
     * @param userId user id
     */
    private static List<HostSystem> getAllSystemStatus(Connection con, Long userId) throws SQLException {

        List<HostSystem> hostSystemList = new ArrayList<>();

        try (PreparedStatement stmt = con.prepareStatement("select * from status where user_id=? order by id asc")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    HostSystem hostSystem = SystemDB.getSystem(con, rs.getLong("id"));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                    hostSystemList.add(hostSystem);
                }
            }
        }

        return hostSystemList;
    }


    /**
     * returns key placement status of system
     *
     * @param systemId system id
     * @param userId   user id
     */
    public static HostSystem getSystemStatus(Long systemId, Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getSystemStatus(con, systemId, userId);
        }
    }

    /**
     * returns key placement status of system
     *
     * @param con      DB connection
     * @param systemId system id
     * @param userId   user id
     */
    public static HostSystem getSystemStatus(Connection con, Long systemId, Long userId) throws SQLException {

        HostSystem hostSystem = null;

        try (PreparedStatement stmt = con.prepareStatement("select * from status where id=? and user_id=?")) {
            stmt.setLong(1, systemId);
            stmt.setLong(2, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    hostSystem = SystemDB.getSystem(con, rs.getLong("id"));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                }
            }
        }

        return hostSystem;
    }


    /**
     * returns the first system that authorized keys has not been tried
     *
     * @param userId user id
     * @return hostSystem systems for authorized_keys replacement
     */
    public static HostSystem getNextPendingSystem(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getNextPendingSystem(con, userId);
        }
    }

    /**
     * returns the first system that authorized keys has not been tried
     *
     * @param con    DB connection
     * @param userId user id
     * @return hostSystem systems for authorized_keys replacement
     */
    public static HostSystem getNextPendingSystem(Connection con, Long userId) throws SQLException {

        HostSystem hostSystem = null;

        try (PreparedStatement stmt = con.prepareStatement("select * from status where status_cd in (?,?,?) and user_id=? order by id asc")) {
            stmt.setString(1, HostSystem.INITIAL_STATUS);
            stmt.setString(2, HostSystem.AUTH_FAIL_STATUS);
            stmt.setString(3, HostSystem.PUBLIC_KEY_FAIL_STATUS);
            stmt.setLong(4, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    hostSystem = SystemDB.getSystem(con, rs.getLong("id"));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                }
            }
        }

        return hostSystem;
    }
}
