/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;


import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.SessionAudit;
import io.bastillion.manage.model.SessionOutput;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.model.User;
import io.bastillion.manage.util.DBUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DB class to store terminal logs for sessions
 */
public class SessionAuditDB {

    public static final String USER_ID = "user_id";
    public static final String FILTER_BY_USER = "username";
    public static final String FILTER_BY_SYSTEM = "display_nm";

    public static final String SORT_BY_FIRST_NM = "first_nm";
    public static final String SORT_BY_LAST_NM = "last_nm";
    public static final String SORT_BY_IP_ADDRESS = "ip_address";
    public static final String SORT_BY_USERNAME = "username";
    public static final String SORT_BY_SESSION_TM = "session_tm";
    /**
     * Columns the session audit list may be ordered by - see
     * {@link SortedSet#toOrderByClause(Set)}. Mirrors the sortable headers in
     * manage/view_sessions.html.
     */
    private static final Set<String> SORTABLE_FIELDS = Set.of(
            SORT_BY_FIRST_NM, SORT_BY_LAST_NM, SORT_BY_IP_ADDRESS, SORT_BY_USERNAME, SORT_BY_SESSION_TM);

    private static final Pattern TERMINAL_CONTROL_PATTERN = Pattern.compile(
            "\u001B\\[[0-9;?]*[ -/]*[@-~]"                       //CSI - colors, cursor movement, screen modes
                    + "|\u001B\\][^\\u0007\u001B]*(?:\\u0007|\u001B\\\\|$)" //OSC - window title
                    + "|\u001B[()][0-9A-B]"                        //charset selection
                    + "|\u001B[=>78cM]"                            //keypad modes, cursor save/restore
                    + "|\\u0007"                                    //bell
                    + "|\\]0;|\\[\\d\\d;\\d\\dm|\\[\\dm"              //bare leftovers logged without the escape char
                    + "|\u001B");                                  //any stray escape char
    // zsh paints this inverse-video percent sign when the previous output did not end
    // with a newline. It is terminal chrome, not command output, and should not appear
    // as a standalone "%" line in recorded audit sessions.
    private static final Pattern ZSH_PROMPT_EOL_MARK_PATTERN = Pattern.compile(
            "\u001B\\[1m\u001B\\[7m%\u001B\\[27m(?:\u001B\\[1m)?\u001B\\[0m");
    //upper bound on how much of a single line without newlines is buffered before it is forced out
    private static final int MAX_LINE_BUFFER = 1024 * 1024;

    private SessionAuditDB() {
    }


    /**
     * deletes audit history for users if after time set in properties file
     *
     * @param con DB connection
     */
    public static void deleteAuditHistory(Connection con) throws SQLException {

        //take today's date and subtract how many days to keep history
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, (-1 * Integer.parseInt(AppConfig.getProperty("deleteAuditLogAfter")))); //subtract
        java.sql.Date date = new java.sql.Date(cal.getTimeInMillis());


        try (PreparedStatement stmt = con.prepareStatement("delete from session_log where session_tm < ?")) {
            stmt.setDate(1, date);
            stmt.execute();
        }
    }


    /**
     * returns sessions based on sort order defined
     *
     * @param sortedSet object that defines sort order
     * @return session list
     */
    public static SortedSet getSessions(SortedSet sortedSet) throws SQLException, GeneralSecurityException {
        List<SessionAudit> outputList = new LinkedList<>();

        String orderBy = sortedSet.toOrderByClause(SORTABLE_FIELDS);

        String sql = "select * from session_log where 1=1 ";
        sql += StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_USER)) ? " and session_log.username like ? " : "";
        sql += StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_SYSTEM)) ? " and session_log.id in ( select session_id from terminal_log where terminal_log.display_nm like ?) " : "";
        sql += orderBy;

        try (Connection con = DBUtils.getConn()) {
            deleteAuditHistory(con);

            try (PreparedStatement stmt = con.prepareStatement(sql)) {
                int i = 1;
                //set filters in prepared statement
                if (StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_USER))) {
                    stmt.setString(i++, sortedSet.getFilterMap().get(FILTER_BY_USER));
                }
                if (StringUtils.isNotEmpty(sortedSet.getFilterMap().get(FILTER_BY_SYSTEM))) {
                    stmt.setString(i, sortedSet.getFilterMap().get(FILTER_BY_SYSTEM));
                }

                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        SessionAudit sessionAudit = new SessionAudit();
                        sessionAudit.setId(rs.getLong("session_log.id"));
                        sessionAudit.setSessionTm(rs.getTimestamp("session_tm"));
                        sessionAudit.setFirstNm(rs.getString("first_nm"));
                        sessionAudit.setLastNm(rs.getString("last_nm"));
                        sessionAudit.setIpAddress(rs.getString("ip_address"));
                        sessionAudit.setUsername(rs.getString("username"));
                        outputList.add(sessionAudit);
                    }
                }
            }
        }

        sortedSet.setItemList(outputList);

        return sortedSet;
    }

    /**
     * insert new session record for user
     *
     * @param user session user
     * @return session id
     */
    public static Long createSessionLog(User user) throws SQLException, GeneralSecurityException {
        //get db connection
        try (Connection con = DBUtils.getConn()) {
            return createSessionLog(con, user);
        }
    }

    /**
     * insert new session record for user
     *
     * @param con  DB connection
     * @param user session user
     * @return session id
     */
    public static Long createSessionLog(Connection con, User user) throws SQLException {
        Long sessionId = null;

        //insert
        try (PreparedStatement stmt = con.prepareStatement("insert into session_log (first_nm, last_nm, username, ip_address) values(?,?,?,?)", Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, user.getFirstNm());
            stmt.setString(2, user.getLastNm());
            stmt.setString(3, user.getUsername());
            stmt.setString(4, user.getIpAddress());
            stmt.execute();
            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs != null && rs.next()) {
                    sessionId = rs.getLong(1);
                }
            }
        }

        return sessionId;
    }


    /**
     * insert new terminal history for user
     *
     * @param sessionOutput output from session terminals
     * @return session id
     */
    public static void insertTerminalLog(SessionOutput sessionOutput) throws SQLException, GeneralSecurityException {
        //get db connection
        try (Connection con = DBUtils.getConn()) {
            insertTerminalLog(con, sessionOutput);
        }
    }

    /**
     * insert new terminal history for user
     *
     * @param con           DB connection
     * @param sessionOutput output from session terminals
     * @return session id
     */
    public static void insertTerminalLog(Connection con, SessionOutput sessionOutput) throws SQLException {

        if (sessionOutput != null && sessionOutput.getSessionId() != null && sessionOutput.getInstanceId() != null && sessionOutput.getOutput() != null && !sessionOutput.getOutput().toString().equals("")) {
            //insert
            try (PreparedStatement stmt = con.prepareStatement("insert into terminal_log (session_id, instance_id, display_nm, username, host, port, output) values(?,?,?,?,?,?,?)")) {
                stmt.setLong(1, sessionOutput.getSessionId());
                stmt.setLong(2, sessionOutput.getInstanceId());
                stmt.setString(3, sessionOutput.getDisplayNm());
                stmt.setString(4, sessionOutput.getUser());
                stmt.setString(5, sessionOutput.getHost());
                stmt.setInt(6, sessionOutput.getPort());
                stmt.setString(7, sessionOutput.getOutput().toString());
                stmt.execute();
            }
        }
    }


    /**
     * streams cleaned terminal output for a user session to the given writer
     *
     * @param sessionId  session id
     * @param instanceId instance id for terminal session
     * @param writer     destination for cleaned terminal output
     */
    public static void streamTerminalLogsForSession(Long sessionId, Integer instanceId, Writer writer) throws SQLException, GeneralSecurityException, IOException {
        //get db connection
        try (Connection con = DBUtils.getConn()) {
            streamTerminalLogsForSession(con, sessionId, instanceId, writer);
        }
    }


    /**
     * streams cleaned terminal output for a user session to the given writer, one line
     * at a time, so the full session log is never held in memory
     *
     * @param con        DB connection
     * @param sessionId  session id
     * @param instanceId instance id for terminal session
     * @param writer     destination for cleaned terminal output
     */
    public static void streamTerminalLogsForSession(Connection con, Long sessionId, Integer instanceId, Writer writer) throws SQLException, IOException {

        try (PreparedStatement stmt = con.prepareStatement("select output from terminal_log where instance_id=? and session_id=? order by log_tm asc")) {
            stmt.setLong(1, instanceId);
            stmt.setLong(2, sessionId);
            try (ResultSet rs = stmt.executeQuery()) {

                //lines are buffered across rows so control sequences split between two output
                //chunks are still cleaned; backspaces never apply across a newline
                StringBuilder line = new StringBuilder();
                while (rs.next()) {
                    String output = rs.getString("output");
                    for (int i = 0; i < output.length(); i++) {
                        char c = output.charAt(i);
                        if (c == '\n') {
                            // zsh commonly submits a command as CR CR LF while bash uses
                            // CR LF. Remove every trailing carriage return so the extra zsh
                            // CR does not render as a blank line in the audit transcript.
                            while (line.length() > 0 && line.charAt(line.length() - 1) == '\r') {
                                line.setLength(line.length() - 1);
                            }
                            writeCleanedLine(writer, line.toString());
                            line.setLength(0);
                        } else {
                            line.append(c);
                            if (line.length() >= MAX_LINE_BUFFER) {
                                writeCleanedLine(writer, line.toString());
                                line.setLength(0);
                            }
                        }
                    }
                }
                if (line.length() > 0) {
                    writeCleanedLine(writer, line.toString());
                }
            }
        }
    }

    /**
     * strips terminal control sequences from a line of output and applies backspaces
     *
     * @param line raw line of terminal output
     * @return cleaned line
     */
    static String cleanLine(String line) {
        String cleaned = cleanAuditLine(line);
        return cleaned == null ? "" : cleaned;
    }

    /**
     * Writes a real terminal line, but drops zsh's visual end-of-line marker along
     * with its newline. Returning an empty string from {@link #cleanLine(String)} is
     * not enough here because genuine empty terminal lines must remain visible.
     */
    private static void writeCleanedLine(Writer writer, String line) throws IOException {
        String cleaned = cleanAuditLine(line);
        if (cleaned != null) {
            writer.write(cleaned);
            writer.write('\n');
        }
    }

    /**
     * @return cleaned terminal text, or {@code null} when the entire line is zsh's
     * visual PROMPT_EOL_MARK and should not be included in an audit replay
     */
    private static String cleanAuditLine(String line) {
        boolean containedTerminalStyling = line.indexOf('\u001B') >= 0;
        Matcher zshEolMarkMatcher = ZSH_PROMPT_EOL_MARK_PATTERN.matcher(line);
        boolean containedZshEolMark = zshEolMarkMatcher.find();
        String withoutZshEolMark = zshEolMarkMatcher.replaceAll("");
        String cleaned = TERMINAL_CONTROL_PATTERN.matcher(withoutZshEolMark).replaceAll("");
        // zsh versions and prompt configurations can append additional cursor/erase
        // sequences to PROMPT_EOL_MARK. If stripping those sequences leaves only the
        // styled marker, discard it. A real, unstyled "%" output line is preserved.
        if ((containedZshEolMark && cleaned.trim().isEmpty())
                || (containedTerminalStyling && "%".equals(cleaned.trim()))) {
            return null;
        }
        if (cleaned.indexOf('\b') < 0) {
            return cleaned;
        }
        StringBuilder sb = new StringBuilder(cleaned.length());
        for (int i = 0; i < cleaned.length(); i++) {
            char c = cleaned.charAt(i);
            if (c == '\b') {
                if (sb.length() > 0) {
                    sb.deleteCharAt(sb.length() - 1);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * returns terminal logs for user session for host system
     *
     * @param con       DB connection
     * @param sessionId session id
     * @return session output for session
     */
    public static List<HostSystem> getHostSystemsForSession(Connection con, Long sessionId) throws SQLException {

        List<HostSystem> hostSystemList = new ArrayList<>();
        try (PreparedStatement stmt = con.prepareStatement("select distinct instance_id, display_nm, username, host, port from terminal_log where session_id=?")) {
            stmt.setLong(1, sessionId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    HostSystem hostSystem = new HostSystem();
                    hostSystem.setDisplayNm(rs.getString("display_nm"));
                    hostSystem.setUser(rs.getString("username"));
                    hostSystem.setHost(rs.getString("host"));
                    hostSystem.setPort(rs.getInt("port"));
                    hostSystem.setInstanceId(rs.getInt("instance_id"));
                    hostSystemList.add(hostSystem);
                }
            }
        }

        return hostSystemList;
    }

    /**
     * returns a list of terminal sessions for session id
     *
     * @param sessionId session id
     * @return terminal sessions with host information
     */
    public static SessionAudit getSessionsTerminals(Long sessionId) throws SQLException, GeneralSecurityException {

        SessionAudit sessionAudit = new SessionAudit();
        String sql = "select * from session_log where session_log.id = ? ";

        try (Connection con = DBUtils.getConn();
             PreparedStatement stmt = con.prepareStatement(sql)) {
            stmt.setLong(1, sessionId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    sessionAudit.setId(rs.getLong("session_log.id"));
                    sessionAudit.setSessionTm(rs.getTimestamp("session_tm"));
                    sessionAudit.setUsername(rs.getString("username"));
                    sessionAudit.setFirstNm(rs.getString("first_nm"));
                    sessionAudit.setLastNm(rs.getString("last_nm"));
                    sessionAudit.setIpAddress(rs.getString("ip_address"));
                    sessionAudit.setHostSystemList(getHostSystemsForSession(con, sessionId));
                }
            }
        }

        return sessionAudit;
    }

}
