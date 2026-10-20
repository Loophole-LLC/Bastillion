/**
 * Copyright (C) 2015 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import io.bastillion.manage.model.UserSettings;
import io.bastillion.manage.util.DBUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * DAO to manage user themes
 */
public class UserThemeDB {

    private UserThemeDB() {
    }

    /**
     * get user theme
     *
     * @param userId object
     * @return user theme object
     */
    public static UserSettings getTheme(Long userId) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            return getTheme(con, userId);
        }
    }

    /**
     * get user theme
     *
     * @param con    DB connection
     * @param userId object
     * @return user theme object
     */
    public static UserSettings getTheme(Connection con, Long userId) throws SQLException {

        UserSettings theme = new UserSettings();

        try (PreparedStatement stmt = con.prepareStatement("select * from user_theme where user_id=?")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    theme.setBg(rs.getString("bg"));
                    theme.setFg(rs.getString("fg"));
                    theme.setUiTheme(rs.getString("ui_theme"));
                    if (StringUtils.isNotEmpty(rs.getString("d1"))) {
                        String[] colors = new String[16];
                        colors[0] = rs.getString("d1");
                        colors[1] = rs.getString("d2");
                        colors[2] = rs.getString("d3");
                        colors[3] = rs.getString("d4");
                        colors[4] = rs.getString("d5");
                        colors[5] = rs.getString("d6");
                        colors[6] = rs.getString("d7");
                        colors[7] = rs.getString("d8");
                        colors[8] = rs.getString("b1");
                        colors[9] = rs.getString("b2");
                        colors[10] = rs.getString("b3");
                        colors[11] = rs.getString("b4");
                        colors[12] = rs.getString("b5");
                        colors[13] = rs.getString("b6");
                        colors[14] = rs.getString("b7");
                        colors[15] = rs.getString("b8");
                        theme.setColors(colors);
                    }
                }
            }
        }

        return theme;
    }


    /**
     * saves user theme
     *
     * @param userId object
     */
    public static void saveTheme(Long userId, UserSettings theme) throws SQLException, GeneralSecurityException {

        try (Connection con = DBUtils.getConn()) {
            saveTheme(con, userId, theme);
        }
    }

    /**
     * saves user theme
     *
     * @param con    DB connection
     * @param userId object
     */
    public static void saveTheme(Connection con, Long userId, UserSettings theme) throws SQLException {

        try (PreparedStatement stmt = con.prepareStatement("delete from user_theme where user_id=?")) {
            stmt.setLong(1, userId);
            stmt.execute();
        }

        if (theme != null) {
            try (PreparedStatement stmt = con.prepareStatement("insert into user_theme(user_id, bg, fg, d1, d2, d3, d4, d5, d6, d7, d8, b1, b2, b3, b4, b5, b6, b7, b8, ui_theme) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
                stmt.setLong(1, userId);
                stmt.setString(2, theme.getBg());
                stmt.setString(3, theme.getFg());
                //if contains all 16 theme colors insert
                if (theme.getColors() != null && theme.getColors().length == 16) {
                    for (int i = 0; i < 16; i++) {
                        stmt.setString(i + 4, theme.getColors()[i]);
                    }
                    //else set to null
                } else {
                    for (int i = 0; i < 16; i++) {
                        stmt.setString(i + 4, null);
                    }
                }
                stmt.setString(20, theme.getUiTheme());
                stmt.execute();
            }
        }
    }

    public static String getUiTheme(Connection con, Long userId) throws SQLException {
        try (PreparedStatement stmt = con.prepareStatement(
                "select ui_theme from user_theme where user_id=?")) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? rs.getString("ui_theme") : UserSettings.DARK;
            }
        }
    }
}
