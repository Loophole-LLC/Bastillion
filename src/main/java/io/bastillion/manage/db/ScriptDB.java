/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;


import io.bastillion.manage.model.Script;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.util.DBUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Set;

/**
 * DAO to manage scripts
 */
public class ScriptDB {

    public static final String DISPLAY_NM = "display_nm";
    public static final String SORT_BY_DISPLAY_NM = DISPLAY_NM;
    /**
     * Columns the script list may be ordered by - see {@link SortedSet#toOrderByClause(Set)}.
     * Mirrors the sortable headers in admin/view_scripts.html.
     */
    private static final Set<String> SORTABLE_FIELDS = Set.of(SORT_BY_DISPLAY_NM);

    private ScriptDB() {
    }


    /**
     * returns scripts based on sort order defined
     *
     * @param sortedSet object that defines sort order
     * @param userId    user id
     * @return sorted script list
     */
    public static SortedSet getScriptSet(SortedSet sortedSet, Long userId) throws SQLException, GeneralSecurityException {

        ArrayList<Script> scriptList = new ArrayList<>();

        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);
        String sql = "select * from scripts where user_id=?" + orderBy;

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql)) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Script script = new Script();
                    script.setId(rs.getLong("id"));
                    script.setDisplayNm(rs.getString(DISPLAY_NM));
                    script.setScript(rs.getString("script"));

                    scriptList.add(script);

                }
            }
        }

        sortedSet.setItemList(scriptList);
        return sortedSet;
    }


    /**
     * returns script base on id
     *
     * @param scriptId script id
     * @param userId   user id
     * @return script object
     */
    public static Script getScript(Long scriptId, Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getScript(con, scriptId, userId);
        }
    }

    /**
     * returns script base on id
     *
     * @param con      DB connection
     * @param scriptId script id
     * @param userId   user id
     * @return script object
     */
    public static Script getScript(Connection con, Long scriptId, Long userId) throws SQLException {

        Script script = null;
        try (PreparedStatement stmt = con.prepareStatement("select * from  scripts where id=? and user_id=?")) {
            stmt.setLong(1, scriptId);
            stmt.setLong(2, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    script = new Script();
                    script.setId(rs.getLong("id"));
                    script.setDisplayNm(rs.getString(DISPLAY_NM));
                    script.setScript(rs.getString("script"));
                }
            }
        }

        return script;
    }

    /**
     * inserts new script
     *
     * @param script script object
     * @param userId user id
     */
    public static void insertScript(Script script, Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("insert into scripts (display_nm, script, user_id) values (?,?,?)")) {
            stmt.setString(1, script.getDisplayNm());
            stmt.setString(2, script.getScript());
            stmt.setLong(3, userId);
            stmt.execute();
        }
    }

    /**
     * updates existing script
     *
     * @param script script object
     * @param userId user id
     */
    public static void updateScript(Script script, Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("update scripts set display_nm=?, script=? where id=? and user_id=?")) {
            stmt.setString(1, script.getDisplayNm());
            stmt.setString(2, script.getScript());
            stmt.setLong(3, script.getId());
            stmt.setLong(4, userId);
            stmt.execute();
        }
    }

    /**
     * deletes script
     *
     * @param scriptId script id
     * @param userId   user id
     */
    public static void deleteScript(Long scriptId, Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement("delete from scripts where id=? and user_id=?")) {
            stmt.setLong(1, scriptId);
            stmt.setLong(2, userId);
            stmt.execute();
        }
    }
}
