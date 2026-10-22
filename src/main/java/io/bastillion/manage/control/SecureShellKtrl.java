/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import com.jcraft.jsch.ChannelShell;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.ScriptDB;
import io.bastillion.manage.db.SessionAuditDB;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.db.SystemStatusDB;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.db.UserThemeDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.SchSession;
import io.bastillion.manage.model.Script;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.model.User;
import io.bastillion.manage.model.UserSchSessions;
import io.bastillion.manage.model.UserSettings;
import io.bastillion.manage.util.SSHUtil;
import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
import loophole.mvc.base.BaseKontroller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This action will create composite ssh terminals to be used
 */
public class SecureShellKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(SecureShellKtrl.class);

    static Map<Long, UserSchSessions> userSchSessionMap = new ConcurrentHashMap<>();

    @Model(name = "systemSelectId", params = {"systemSelectId"})
    List<Long> systemSelectId = new ArrayList<>();
    @Model(name = "currentSystemStatus")
    HostSystem currentSystemStatus;
    @Model(name = "pendingSystemStatus", params = {"pendingSystemStatus.id"})
    HostSystem pendingSystemStatus;
    @Model(name = "password", params = {"password"})
    String password;
    @Model(name = "passphrase", params = {"passphrase"})
    String passphrase;
    @Model(name = "id", params = {"id"})
    Integer id;
    @Model(name = "systemList")
    List<HostSystem> systemList = new ArrayList<>();
    @Model(name = "allocatedSystemList")
    List<HostSystem> allocatedSystemList = new ArrayList<>();
    @Model(name = "userSettings", params = {
            "userSettings.ptyColumns",
            "userSettings.ptyRows",
            "userSettings.ptyWidth",
            "userSettings.ptyHeight"})
    UserSettings userSettings;
    @Model(name = "script", params = {"script.id"})
    Script script = new Script();


    public SecureShellKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    public static Map<Long, UserSchSessions> getUserSchSessionMap() {
        return userSchSessionMap;
    }

    public static void setUserSchSessionMap(Map<Long, UserSchSessions> userSchSessionMap) {
        SecureShellKtrl.userSchSessionMap = userSchSessionMap;
    }

    /**
     * creates composite terminals if there are errors or authentication issues.
     */
    @Kontrol(path = "/admin/createTerms", method = MethodType.POST)
    public String createTerms() throws ServletException {

        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            Long sessionId = AuthUtil.getSessionId(getRequest().getSession());
            if (pendingSystemStatus != null && pendingSystemStatus.getId() != null) {


                //get status
                currentSystemStatus = SystemStatusDB.getSystemStatus(pendingSystemStatus.getId(), userId);
                //if initial status run script
                if (currentSystemStatus != null
                        && (HostSystem.INITIAL_STATUS.equals(currentSystemStatus.getStatusCd())
                        || HostSystem.AUTH_FAIL_STATUS.equals(currentSystemStatus.getStatusCd())
                        || HostSystem.PUBLIC_KEY_FAIL_STATUS.equals(currentSystemStatus.getStatusCd()))
                ) {

                    //set current session
                    currentSystemStatus = SSHUtil.openSSHTermOnSystem(passphrase, password, userId, sessionId, currentSystemStatus, userSchSessionMap);

                }
                if (currentSystemStatus != null
                        && (HostSystem.AUTH_FAIL_STATUS.equals(currentSystemStatus.getStatusCd())
                        || HostSystem.PUBLIC_KEY_FAIL_STATUS.equals(currentSystemStatus.getStatusCd()))) {

                    pendingSystemStatus = currentSystemStatus;

                } else {

                    pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
                    //if success loop through systems until finished or need password
                    while (pendingSystemStatus != null && currentSystemStatus != null && HostSystem.SUCCESS_STATUS.equals(currentSystemStatus.getStatusCd())) {
                        currentSystemStatus = SSHUtil.openSSHTermOnSystem(passphrase, password, userId, sessionId, pendingSystemStatus, userSchSessionMap);
                        pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);
                    }


                }

            }
            //set system list if no pending systems
            if (SystemStatusDB.getNextPendingSystem(userId) == null) {
                setSystemList(userId, sessionId);

                //set allocated systems for connect to
                SortedSet sortedSet = new SortedSet();
                sortedSet.setOrderByField(SystemDB.SORT_BY_NAME);
                if (Auth.MANAGER.equals(AuthUtil.getUserType(getRequest().getSession()))) {
                    sortedSet = SystemDB.getSystemSet(sortedSet);
                } else {
                    sortedSet = SystemDB.getUserSystemSet(sortedSet, userId);
                }
                if (sortedSet.getItemList() != null) {
                    allocatedSystemList = (List<HostSystem>) sortedSet.getItemList();
                }
                //set theme
                this.userSettings = UserThemeDB.getTheme(userId);

            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }


        return "/admin/secure_shell.html";
    }

    @Kontrol(path = "/admin/getNextPendingSystemForTerms", method = MethodType.GET)
    public String getNextPendingSystemForTerms() throws ServletException {
        Long userId;
        try {
            userId = AuthUtil.getUserId(getRequest().getSession());
            currentSystemStatus = SystemStatusDB.getSystemStatus(pendingSystemStatus.getId(), userId);
            currentSystemStatus.setErrorMsg("Auth fail");
            currentSystemStatus.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);


            SystemStatusDB.updateSystemStatus(currentSystemStatus, userId);
            SystemDB.updateSystem(currentSystemStatus);

            pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);

            //set system list if no pending systems
            if (pendingSystemStatus == null) {
                setSystemList(userId, AuthUtil.getSessionId(getRequest().getSession()));
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return "/admin/secure_shell.html";
    }

    @Kontrol(path = "/admin/selectSystemsForCompositeTerms", method = MethodType.GET)
    public String selectSystemsForCompositeTerms() throws ServletException {


        if (systemSelectId != null && !systemSelectId.isEmpty()) {
            try {
                Long userId = AuthUtil.getUserId(getRequest().getSession());

                SystemStatusDB.setInitialSystemStatus(systemSelectId, userId, AuthUtil.getUserType(getRequest().getSession()));
                pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);

                User user = UserDB.getUser(userId);
                user.setIpAddress(AuthUtil.getClientIPAddress(getRequest()));

                AuthUtil.setSessionId(getRequest().getSession(), SessionAuditDB.createSessionLog(user));
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }

        return "/admin/secure_shell.html";
    }

    @Kontrol(path = "/admin/exitTerms", method = MethodType.GET)
    public String exitTerms() {

        return "redirect:/admin/menu.html";
    }

    @Kontrol(path = "/admin/disconnectTerm", method = MethodType.GET)
    public String disconnectTerm() throws ServletException {
        Long sessionId = null;
        try {
            sessionId = AuthUtil.getSessionId(getRequest().getSession());
        } catch (GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        if (SecureShellKtrl.getUserSchSessionMap() != null) {
            UserSchSessions userSchSessions = SecureShellKtrl.getUserSchSessionMap().get(sessionId);
            if (userSchSessions != null) {
                SchSession schSession = userSchSessions.getSchSessionMap().get(id);

                //disconnect ssh session
                if (schSession != null) {
                    if (schSession.getChannel() != null)
                        schSession.getChannel().disconnect();
                    if (schSession.getSession() != null)
                        schSession.getSession().disconnect();
                    schSession.setChannel(null);
                    schSession.setSession(null);
                    schSession.setInputToChannel(null);
                    schSession.setCommander(null);
                    schSession.setOutFromChannel(null);
                }
                //remove from map
                userSchSessions.getSchSessionMap().remove(id);
            }
        }

        return null;
    }

    @Kontrol(path = "/admin/createSession", method = MethodType.GET)
    public String createSession() throws ServletException {

        Long userId = null;
        try {
            userId = AuthUtil.getUserId(getRequest().getSession());
        } catch (GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        if (systemSelectId != null && !systemSelectId.isEmpty()) {

            try {
                SystemStatusDB.setInitialSystemStatus(systemSelectId, userId, AuthUtil.getUserType(getRequest().getSession()));

                pendingSystemStatus = SystemStatusDB.getNextPendingSystem(userId);

                createTerms();
            } catch (SQLException | GeneralSecurityException | ServletException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }

        }

        return null;
    }

    @Kontrol(path = "/admin/setPtyType", method = MethodType.GET)
    public String setPtyType() throws ServletException {

        Long sessionId = null;
        try {
            sessionId = AuthUtil.getSessionId(getRequest().getSession());
        } catch (GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        if (SecureShellKtrl.getUserSchSessionMap() != null) {
            UserSchSessions userSchSessions = SecureShellKtrl.getUserSchSessionMap().get(sessionId);
            if (userSchSessions != null && userSchSessions.getSchSessionMap() != null) {

                SchSession schSession = userSchSessions.getSchSessionMap().get(id);

                if (schSession != null && schSession.getChannel() instanceof ChannelShell channel
                        && userSettings.getPtyColumns() != null && userSettings.getPtyRows() != null
                        && userSettings.getPtyWidth() != null && userSettings.getPtyHeight() != null) {
                    int columns = Math.max(1, Math.min(userSettings.getPtyColumns(), 1000));
                    int rows = Math.max(1, Math.min(userSettings.getPtyRows(), 1000));
                    int width = Math.max(1, userSettings.getPtyWidth());
                    int height = Math.max(1, userSettings.getPtyHeight());
                    channel.setPtySize(columns, rows, width, height);
                    schSession.setChannel(channel);
                }

            }

        }

        return null;
    }

    /**
     * set system list once all connections have been attempted
     *
     * @param userId    user id
     * @param sessionId session id
     */
    private void setSystemList(Long userId, Long sessionId) throws ServletException {


        //check user map
        if (userSchSessionMap != null && !userSchSessionMap.isEmpty() && userSchSessionMap.get(sessionId) != null) {

            //get user sessions
            Map<Integer, SchSession> schSessionMap = userSchSessionMap.get(sessionId).getSchSessionMap();


            for (SchSession schSession : schSessionMap.values()) {
                //add to host system list
                systemList.add(schSession.getHostSystem());
                //run script it exists
                if (script != null && script.getId() != null && script.getId() > 0
                        && schSession.getCommander() != null) {
                    try {
                        script = ScriptDB.getScript(script.getId(), userId);
                        BufferedReader reader = new BufferedReader(new StringReader(script.getScript()));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            schSession.getCommander().println(line);
                        }
                    } catch (SQLException | IOException | GeneralSecurityException ex) {
                        log.error(ex.toString(), ex);
                        throw new ServletException(ex.toString(), ex);
                    }
                }
            }
        }

    }
}

