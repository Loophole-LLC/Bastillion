package io.bastillion.manage.socket;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import io.bastillion.common.util.AppConfig;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.control.SecureShellKtrl;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.model.SchSession;
import io.bastillion.manage.model.UserSchSessions;
import io.bastillion.manage.task.SentOutputTask;
import io.bastillion.manage.util.SessionOutputUtil;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpSession;
import jakarta.websocket.*;
import jakarta.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * class to run commands and start thread to send web socket terminal output
 */
@ServerEndpoint(value = "/admin/terms.ws", configurator = GetHttpSessionConfigurator.class)
@SuppressWarnings("unchecked")
public class SecureShellWS {

    private static final Logger log = LoggerFactory.getLogger(SecureShellWS.class);

    private HttpSession httpSession = null;
    private Session session = null;
    private Long sessionId = null;

    @OnOpen
    public void onOpen(Session session, EndpointConfig config) {

        if (this.httpSession == null) {
            this.httpSession = (HttpSession) config.getUserProperties().get(HttpSession.class.getName());
        }

        // The servlet container does not run AuthFilter (mapped to /admin/*) against the
        // WebSocket upgrade request for this endpoint, so this connection would otherwise be
        // reachable with no session at all - explicitly require the same valid, non-expired
        // admin auth that AuthFilter enforces for the rest of /admin/* before doing anything
        // else, rather than relying on a downstream NPE (e.g. UserDB.getUser(null)) to
        // incidentally kill unauthenticated connections.
        if (!isAuthenticated()) {
            try {
                session.close(new CloseReason(CloseReason.CloseCodes.VIOLATED_POLICY, "Not authenticated"));
            } catch (IOException ex) {
                log.error(ex.toString(), ex);
            }
            return;
        }

        //set websocket timeout
        if (StringUtils.isNotEmpty(AppConfig.getProperty("websocketTimeout"))) {
            session.setMaxIdleTimeout(Long.parseLong(AppConfig.getProperty("websocketTimeout")) * 60000);
        } else {
            session.setMaxIdleTimeout(0);
        }

        Runnable run = null;
        try {
            this.sessionId = AuthUtil.getSessionId(httpSession);
            this.session = session;

            run = new SentOutputTask(sessionId, session, UserDB.getUser(AuthUtil.getUserId(httpSession)));
            Thread thread = new Thread(run);
            thread.start();
        } catch (GeneralSecurityException | SQLException ex) {
            log.error(ex.toString(), ex);
        }

    }

    /**
     * Applies AuthFilter's check (valid, non-expired admin auth token) since that filter is
     * never invoked for this endpoint's WebSocket upgrade request. Deliberately does not
     * extend the session timeout the way AuthFilter does - a terminal left open should not
     * keep the session alive on its own.
     */
    private boolean isAuthenticated() {
        try {
            return AuthUtil.authenticatedUserType(httpSession) != null;
        } catch (GeneralSecurityException | SQLException | java.text.ParseException ex) {
            log.error(ex.toString(), ex);
            return false;
        }
    }


    @OnMessage
    public void onMessage(String message) {

        if (session.isOpen() && StringUtils.isNotEmpty(message) && !"heartbeat".equals(message)) {

            try {
                Map jsonRoot = new Gson().fromJson(message, Map.class);

                String command = (String) jsonRoot.get("command");

                Integer keyCode = null;
                Double keyCodeDbl = (Double) jsonRoot.get("keyCode");
                if (keyCodeDbl != null) {
                    keyCode = keyCodeDbl.intValue();
                }

                for (String idStr : (ArrayList<String>) jsonRoot.get("id")) {
                    Integer id = Integer.parseInt(idStr);

                    //get servletRequest.getSession() for user
                    UserSchSessions userSchSessions = SecureShellKtrl.getUserSchSessionMap().get(sessionId);
                    if (userSchSessions != null) {
                        SchSession schSession = userSchSessions.getSchSessionMap().get(id);
                        // id can reference a terminal that's already closed on this end (a
                        // stale browser tab, a race with onClose), or one whose SSH handshake
                        // hasn't finished yet (the instance id is reserved in the map before
                        // the commander is set) - ignore it rather than NPE either way.
                        if (schSession == null || schSession.getCommander() == null) {
                            continue;
                        }
                        if (keyCode != null) {
                            if (keyMap.containsKey(keyCode)) {
                                schSession.getCommander().write(keyMap.get(keyCode));
                            }
                        } else {
                            schSession.getCommander().print(command);
                        }
                    }

                }
                //update timeout
                AuthUtil.setTimeout(httpSession);
            } catch (IllegalStateException | JsonSyntaxException | IOException ex) {
                log.error(ex.toString(), ex);
            }
        }
    }

    @OnError
    public void onError(Session session, Throwable t) {
        log.error("Error occurred in WebSocket session ID: {} (Bastillion Session ID: {}) - Exception: {}",
                session != null ? session.getId() : "unknown",
                this.sessionId != null ? this.sessionId : "unknown",
                t.toString(),
                t);
    }


    @OnClose
    public void onClose() {

        // Authentication can reject a socket before a Bastillion session id is assigned.
        // The container may still invoke onClose for that rejected connection.
        if (sessionId == null) {
            return;
        }

        if (SecureShellKtrl.getUserSchSessionMap() != null) {
            UserSchSessions userSchSessions = SecureShellKtrl.getUserSchSessionMap().get(sessionId);
            if (userSchSessions != null) {
                Map<Integer, SchSession> schSessionMap = userSchSessions.getSchSessionMap();

                // Work from a snapshot. Removing entries while iterating over keySet can
                // throw ConcurrentModificationException and leave SSH sessions connected.
                for (SchSession schSession : new ArrayList<>(schSessionMap.values())) {
                    if (schSession == null) {
                        continue;
                    }
                    if (schSession.getChannel() != null) {
                        schSession.getChannel().disconnect();
                    }
                    if (schSession.getSession() != null) {
                        schSession.getSession().disconnect();
                    }
                    schSession.setChannel(null);
                    schSession.setSession(null);
                    schSession.setInputToChannel(null);
                    schSession.setCommander(null);
                    schSession.setOutFromChannel(null);
                }


                //clear and remove session map for user
                schSessionMap.clear();
                SecureShellKtrl.getUserSchSessionMap().remove(sessionId);
                SessionOutputUtil.removeUserSession(sessionId);
            }
        }


    }


    /**
     * Maps key press events to the ascii values
     */
    static Map<Integer, byte[]> keyMap = new HashMap<>();

    static {
        //ESC
        keyMap.put(27, new byte[]{(byte) 0x1b});
        //ENTER
        keyMap.put(13, new byte[]{(byte) 0x0d});
        //LEFT
        keyMap.put(37, new byte[]{(byte) 0x1b, (byte) 0x4f, (byte) 0x44});
        //UP
        keyMap.put(38, new byte[]{(byte) 0x1b, (byte) 0x4f, (byte) 0x41});
        //RIGHT
        keyMap.put(39, new byte[]{(byte) 0x1b, (byte) 0x4f, (byte) 0x43});
        //DOWN
        keyMap.put(40, new byte[]{(byte) 0x1b, (byte) 0x4f, (byte) 0x42});
        //BS
        keyMap.put(8, new byte[]{(byte) 0x7f});
        //TAB
        keyMap.put(9, new byte[]{(byte) 0x09});
        //CTR
        keyMap.put(17, new byte[]{});
        //DEL
        keyMap.put(46, "\033[3~".getBytes());
        //CTR-A
        keyMap.put(65, new byte[]{(byte) 0x01});
        //CTR-B
        keyMap.put(66, new byte[]{(byte) 0x02});
        //CTR-C
        keyMap.put(67, new byte[]{(byte) 0x03});
        //CTR-D
        keyMap.put(68, new byte[]{(byte) 0x04});
        //CTR-E
        keyMap.put(69, new byte[]{(byte) 0x05});
        //CTR-F
        keyMap.put(70, new byte[]{(byte) 0x06});
        //CTR-G
        keyMap.put(71, new byte[]{(byte) 0x07});
        //CTR-H
        keyMap.put(72, new byte[]{(byte) 0x08});
        //CTR-I
        keyMap.put(73, new byte[]{(byte) 0x09});
        //CTR-J
        keyMap.put(74, new byte[]{(byte) 0x0A});
        //CTR-K
        keyMap.put(75, new byte[]{(byte) 0x0B});
        //CTR-L
        keyMap.put(76, new byte[]{(byte) 0x0C});
        //CTR-M
        keyMap.put(77, new byte[]{(byte) 0x0D});
        //CTR-N
        keyMap.put(78, new byte[]{(byte) 0x0E});
        //CTR-O
        keyMap.put(79, new byte[]{(byte) 0x0F});
        //CTR-P
        keyMap.put(80, new byte[]{(byte) 0x10});
        //CTR-Q
        keyMap.put(81, new byte[]{(byte) 0x11});
        //CTR-R
        keyMap.put(82, new byte[]{(byte) 0x12});
        //CTR-S
        keyMap.put(83, new byte[]{(byte) 0x13});
        //CTR-T
        keyMap.put(84, new byte[]{(byte) 0x14});
        //CTR-U
        keyMap.put(85, new byte[]{(byte) 0x15});
        //CTR-V
        keyMap.put(86, new byte[]{(byte) 0x16});
        //CTR-W
        keyMap.put(87, new byte[]{(byte) 0x17});
        //CTR-X
        keyMap.put(88, new byte[]{(byte) 0x18});
        //CTR-Y
        keyMap.put(89, new byte[]{(byte) 0x19});
        //CTR-Z
        keyMap.put(90, new byte[]{(byte) 0x1A});
        //CTR-[
        keyMap.put(219, new byte[]{(byte) 0x1B});
        //CTR-]
        keyMap.put(221, new byte[]{(byte) 0x1D});
        //INSERT
        keyMap.put(45, "\033[2~".getBytes());
        //PG UP
        keyMap.put(33, "\033[5~".getBytes());
        //PG DOWN
        keyMap.put(34, "\033[6~".getBytes());
        //END
        keyMap.put(35, "\033[4~".getBytes());
        //HOME
        keyMap.put(36, "\033[1~".getBytes());

    }

}
