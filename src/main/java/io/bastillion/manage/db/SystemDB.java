/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.util.DBUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;


/**
 * DAO used to manage systems
 */
public class SystemDB {

    public static final String AUTHORIZED_KEYS = "authorized_keys";
    public static final String FILTER_BY_PROFILE_ID = "profile_id";

    public static final String DISPLAY_NM = "display_nm";
    public static final String SORT_BY_NAME = DISPLAY_NM;
    public static final String SORT_BY_USER = "username";
    public static final String SORT_BY_HOST = "host";
    public static final String STATUS_CD = "status_cd";
    public static final String PROFILE_ID = "profile_id";
    public static final String SORT_BY_STATUS = STATUS_CD;
    /**
     * Columns the system lists may be ordered by - see {@link SortedSet#toOrderByClause(Set)}.
     * Mirrors the sortable headers in admin/view_systems.html and manage/view_systems.html.
     */
    private static final Set<String> SORTABLE_FIELDS =
            Set.of(SORT_BY_NAME, SORT_BY_USER, SORT_BY_HOST, SORT_BY_STATUS);

    private SystemDB() {
    }


    /**
     * method to do order by based on the sorted set object for systems for user
     *
     * @param sortedSet sorted set object
     * @param userId    user id
     * @return sortedSet with list of host systems
     */
    public static SortedSet getUserSystemSet(SortedSet sortedSet, Long userId) throws SQLException, GeneralSecurityException {
        List<HostSystem> hostSystemList = new ArrayList<>();

        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);
        String sql = "select * from system where id in (select distinct system_id from  system_map m, user_map um where m.profile_id=um.profile_id and um.user_id=? ";
        //if profile id exists add to statement
        sql += StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_PROFILE_ID)) ? " and um.profile_id=? " : "";
        sql += ")" + orderBy;

        //get user for auth token
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql)) {
            stmt.setLong(1, userId);
            //filter by profile id if exists
            if (StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_PROFILE_ID))) {
                stmt.setLong(2, Long.parseLong(sortedSet.getFilterMap().get(FILTER_BY_PROFILE_ID)));
            }

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    HostSystem hostSystem = new HostSystem();
                    hostSystem.setId(rs.getLong("id"));
                    hostSystem.setDisplayNm(rs.getString(DISPLAY_NM));
                    hostSystem.setUser(rs.getString("username"));
                    hostSystem.setHost(rs.getString("host"));
                    hostSystem.setPort(rs.getInt("port"));
                    hostSystem.setAuthorizedKeys(rs.getString(AUTHORIZED_KEYS));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                    hostSystemList.add(hostSystem);
                }
            }
        }

        sortedSet.setItemList(hostSystemList);
        return sortedSet;
    }


    /**
     * method to do order by based on the sorted set object for systems
     *
     * @param sortedSet sorted set object
     * @return sortedSet with list of host systems
     * @profileId check if system is apart of given profile
     */
    public static SortedSet getSystemSet(SortedSet sortedSet, Long profileId) throws SQLException, GeneralSecurityException {
        List<HostSystem> hostSystemList = new ArrayList<>();

        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);
        String sql = "select s.*, m.profile_id from  system s left join system_map  m on m.system_id = s.id and m.profile_id = ?" + orderBy;

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql)) {
            stmt.setLong(1, profileId);
            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    HostSystem hostSystem = new HostSystem();
                    hostSystem.setId(rs.getLong("id"));
                    hostSystem.setDisplayNm(rs.getString(DISPLAY_NM));
                    hostSystem.setUser(rs.getString("username"));
                    hostSystem.setHost(rs.getString("host"));
                    hostSystem.setPort(rs.getInt("port"));
                    hostSystem.setAuthorizedKeys(rs.getString(AUTHORIZED_KEYS));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                    hostSystem.setChecked(profileId != null && profileId.equals(rs.getLong(PROFILE_ID)));
                    hostSystemList.add(hostSystem);
                }
            }
        }

        sortedSet.setItemList(hostSystemList);
        return sortedSet;
    }

    /**
     * method to do order by based on the sorted set object for systems
     *
     * @param sortedSet sorted set object
     * @return sortedSet with list of host systems
     */
    public static SortedSet getSystemSet(SortedSet sortedSet) throws SQLException, GeneralSecurityException {
        List<HostSystem> hostSystemList = new ArrayList<>();

        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);
        String sql = "select * from  system s ";
        //if profile id exists add to statement
        sql += StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_PROFILE_ID)) ? ",system_map m where s.id=m.system_id and m.profile_id=?" : "";
        sql += orderBy;

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql)) {
            if (StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_PROFILE_ID))) {
                stmt.setLong(1, Long.parseLong(sortedSet.getFilterMap().get(FILTER_BY_PROFILE_ID)));
            }
            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    HostSystem hostSystem = new HostSystem();
                    hostSystem.setId(rs.getLong("id"));
                    hostSystem.setDisplayNm(rs.getString(DISPLAY_NM));
                    hostSystem.setUser(rs.getString("username"));
                    hostSystem.setHost(rs.getString("host"));
                    hostSystem.setPort(rs.getInt("port"));
                    hostSystem.setAuthorizedKeys(rs.getString(AUTHORIZED_KEYS));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                    hostSystemList.add(hostSystem);
                }
            }
        }

        sortedSet.setItemList(hostSystemList);
        return sortedSet;
    }


    /**
     * returns system by id
     *
     * @param id system id
     * @return system
     */
    public static HostSystem getSystem(Long id) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getSystem(con, id);
        }
    }


    /**
     * returns system by id
     *
     * @param con DB connection
     * @param id  system id
     * @return system
     */
    public static HostSystem getSystem(Connection con, Long id) throws SQLException {

        HostSystem hostSystem = null;

        try (PreparedStatement stmt = con.prepareStatement("select * from  system where id=?")) {
            stmt.setLong(1, id);
            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    hostSystem = new HostSystem();
                    hostSystem.setId(rs.getLong("id"));
                    hostSystem.setDisplayNm(rs.getString(DISPLAY_NM));
                    hostSystem.setUser(rs.getString("username"));
                    hostSystem.setHost(rs.getString("host"));
                    hostSystem.setPort(rs.getInt("port"));
                    hostSystem.setAuthorizedKeys(rs.getString(AUTHORIZED_KEYS));
                    hostSystem.setStatusCd(rs.getString(STATUS_CD));
                }
            }
        }

        return hostSystem;
    }


    /**
     * returns the total number of registered systems, for license enforcement
     */
    public static int getSystemCount() throws SQLException, GeneralSecurityException {

        int count = 0;
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("select count(*) from system");
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                count = rs.getInt(1);
            }
        }

        return count;
    }

    /**
     * inserts host system into DB
     *
     * @param hostSystem host system object
     * @return user id
     */
    public static Long insertSystem(HostSystem hostSystem) throws SQLException, GeneralSecurityException {

        Long userId = null;
        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("insert into system (display_nm, username, host, port, authorized_keys, status_cd) values (?,?,?,?,?,?)", PreparedStatement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, hostSystem.getDisplayNm());
            stmt.setString(2, hostSystem.getUser());
            stmt.setString(3, hostSystem.getHost());
            stmt.setInt(4, hostSystem.getPort());
            stmt.setString(5, hostSystem.getAuthorizedKeys());
            stmt.setString(6, hostSystem.getStatusCd());
            stmt.execute();

            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next()) {
                    userId = rs.getLong(1);
                }
            }
        }

        return userId;
    }

    /**
     * updates host system record
     *
     * @param hostSystem host system object
     */
    public static void updateSystem(HostSystem hostSystem) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("update system set display_nm=?, username=?, host=?, port=?, authorized_keys=?, status_cd=?  where id=?")) {
            stmt.setString(1, hostSystem.getDisplayNm());
            stmt.setString(2, hostSystem.getUser());
            stmt.setString(3, hostSystem.getHost());
            stmt.setInt(4, hostSystem.getPort());
            stmt.setString(5, hostSystem.getAuthorizedKeys());
            stmt.setString(6, hostSystem.getStatusCd());
            stmt.setLong(7, hostSystem.getId());
            stmt.execute();
        }
    }

    /**
     * deletes host system
     *
     * @param hostSystemId host system id
     */
    public static void deleteSystem(Long hostSystemId) throws SQLException, GeneralSecurityException {


        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("delete from system where id=?")) {
            stmt.setLong(1, hostSystemId);
            stmt.execute();
        }
    }

    /**
     * returns all systems
     *
     * @return system list
     */
    public static List<HostSystem> getAllSystems() throws SQLException, GeneralSecurityException {

        List<HostSystem> hostSystemList = new ArrayList<>();


        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("select * from system");
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                HostSystem hostSystem = new HostSystem();
                hostSystem.setId(rs.getLong("id"));
                hostSystem.setDisplayNm(rs.getString(DISPLAY_NM));
                hostSystem.setUser(rs.getString("username"));
                hostSystem.setHost(rs.getString("host"));
                hostSystem.setPort(rs.getInt("port"));
                hostSystem.setAuthorizedKeys(rs.getString(AUTHORIZED_KEYS));
                hostSystem.setStatusCd(rs.getString(STATUS_CD));
                hostSystemList.add(hostSystem);
            }
        }

        return hostSystemList;
    }


    /**
     * returns all system ids
     *
     * @param con DB connection
     * @return system
     */
    public static List<Long> getAllSystemIds(Connection con) throws SQLException {

        List<Long> systemIdList = new ArrayList<>();

        try (PreparedStatement stmt = con.prepareStatement("select * from system");
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                systemIdList.add(rs.getLong("id"));
            }
        }

        return systemIdList;

    }

    /**
     * returns all system ids for user
     *
     * @param con    DB connection
     * @param userId user id
     * @return system
     */
    public static List<Long> getAllSystemIdsForUser(Connection con, Long userId) throws SQLException {

        List<Long> systemIdList = new ArrayList<>();


        try (PreparedStatement stmt = con.prepareStatement("select distinct system_id from system_map m, user_map um, system s where m.profile_id=um.profile_id and um.user_id=?")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    systemIdList.add(rs.getLong("system_id"));
                }
            }
        }

        return systemIdList;

    }

    /**
     * returns all system ids for user
     *
     * @param userId user id
     * @return system
     */
    public static List<Long> getAllSystemIdsForUser(Long userId) throws SQLException, GeneralSecurityException {
        try (Connection con = DBUtils.getConn()) {
            return getAllSystemIdsForUser(con, userId);
        }
    }

    /**
     * returns all system ids
     *
     * @return system
     */
    public static List<Long> getAllSystemIds() throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getAllSystemIds(con);
        }
    }

    /**
     * method to check system permissions for user
     *
     * @param con                DB connection
     * @param systemSelectIdList list of system ids to check
     * @param userId             user id
     * @return only system ids that user has perms for
     */
    public static List<Long> checkSystemPerms(Connection con, List<Long> systemSelectIdList, Long userId) throws SQLException {

        List<Long> systemIdList = new ArrayList<>();
        List<Long> userSystemIdList = getAllSystemIdsForUser(con, userId);

        for (Long systemId : userSystemIdList) {
            if (systemSelectIdList.contains(systemId)) {
                systemIdList.add(systemId);
            }
        }

        return systemIdList;
    }

}
