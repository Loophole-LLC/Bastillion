/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.util;

import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.util.EncryptionUtil;
import org.apache.commons.lang3.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Pattern;


/**
 * Utility to obtain the authentication token from the http session and the user id from the auth token
 */
public class AuthUtil {

    public static final String SESSION_ID = "sessionId";
    public static final String USER_ID = "userId";
    public static final String USERNAME = "username";
    public static final String AUTH_TOKEN = "authToken";
    public static final String TIMEOUT = "timeout";
    private static final String TIMEOUT_FORMAT = "MMddyyyyHHmmss";

    // Longest possible IPv6 literal with an embedded IPv4 part and a zone id, comfortably.
    private static final int MAX_IP_LITERAL_LENGTH = 45;
    private static final Pattern IPV4 = Pattern.compile(
            "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");
    // Permissive on IPv6 shape rather than enumerating every valid form, but not so permissive
    // that it stops doing its job: the previous expression matched any run of hex digits and
    // colons, so ":", "::::::::" and "a:" all passed. With clientIPHeader set, that let a
    // client mint a fresh throttle key - and a fresh audit-log "IP" - on every request, which
    // is exactly what parsing the header was meant to stop. Requires at least two hex groups,
    // allows the "::" elision, an embedded IPv4 tail, and a zone id, which the previous
    // comment claimed was covered when "%" was not even in the character class.
    private static final Pattern IPV6 = Pattern.compile(
            "(?=.*[0-9A-Fa-f])[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}"
                    + "(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){0,3}(%[0-9A-Za-z._-]{1,32})?");

    private AuthUtil() {
    }

    /**
     * query session for OTP shared secret
     *
     * @param session http session
     * @return shared secret
     */
    public static String getOTPSecret(HttpSession session) throws GeneralSecurityException {
        String secret = (String) session.getAttribute("otp_secret");
        secret = EncryptionUtil.decrypt(secret);
        return secret;
    }

    /**
     * set authentication type
     *
     * @param session  http session
     * @param authType authentication type
     */
    public static void setAuthType(HttpSession session, String authType) {
        if (authType != null) {
            session.setAttribute("authType", authType);
        }
    }

    /**
     * query authentication type
     *
     * @param session http session
     * @return authentication type
     */
    public static String getAuthType(HttpSession session) {
        String authType = (String) session.getAttribute("authType");
        return authType;
    }

    /**
     * set user type
     *
     * @param session  http session
     * @param userType user type
     */
    public static void setUserType(HttpSession session, String userType) {
        if (userType != null) {
            session.setAttribute("userType", userType);
        }
    }

    /**
     * query user type
     *
     * @param session http session
     * @return user type
     */
    public static String getUserType(HttpSession session) {
        String userType = (String) session.getAttribute("userType");
        return userType;
    }

    /**
     * set session id
     *
     * @param session   http session
     * @param sessionId session id
     */
    public static void setSessionId(HttpSession session, Long sessionId) throws GeneralSecurityException {
        if (sessionId != null) {
            session.setAttribute(SESSION_ID, EncryptionUtil.encrypt(sessionId.toString()));
        }
    }

    /**
     * query session id
     *
     * @param session http session
     * @return session id
     */
    public static Long getSessionId(HttpSession session) throws GeneralSecurityException {
        Long sessionId = null;
        String sessionIdStr = EncryptionUtil.decrypt((String) session.getAttribute(SESSION_ID));
        if (sessionIdStr != null && !sessionIdStr.trim().equals("")) {
            sessionId = Long.parseLong(sessionIdStr);
        }
        return sessionId;
    }

    /**
     * query session for user id
     *
     * @param session http session
     * @return user id
     */
    public static Long getUserId(HttpSession session) throws GeneralSecurityException {
        Long userId = null;
        String userIdStr = EncryptionUtil.decrypt((String) session.getAttribute(USER_ID));
        if (userIdStr != null && !userIdStr.trim().equals("")) {
            userId = Long.parseLong(userIdStr);
        }
        return userId;
    }

    /**
     * query session for the username
     *
     * @param session http session
     * @return username
     */
    public static String getUsername(HttpSession session) {
        return (String) session.getAttribute(USERNAME);
    }

    /**
     * query session for authentication token
     *
     * @param session http session
     * @return authentication token
     */
    public static String getAuthToken(HttpSession session) throws GeneralSecurityException {
        String authToken = (String) session.getAttribute(AUTH_TOKEN);
        authToken = EncryptionUtil.decrypt(authToken);
        return authToken;
    }

    /**
     * query session for timeout
     *
     * @param session http session
     * @return timeout string
     */
    public static String getTimeout(HttpSession session) {
        String timeout = (String) session.getAttribute(TIMEOUT);
        return timeout;
    }

    /**
     * set session OTP shared secret
     *
     * @param session http session
     * @param secret  shared secret
     */
    public static void setOTPSecret(HttpSession session, String secret) throws GeneralSecurityException {
        if (secret != null && !secret.trim().equals("")) {
            session.setAttribute("otp_secret", EncryptionUtil.encrypt(secret));
        }
    }


    /**
     * set session user id
     *
     * @param session http session
     * @param userId  user id
     */
    public static void setUserId(HttpSession session, Long userId) throws GeneralSecurityException {
        if (userId != null) {
            session.setAttribute(USER_ID, EncryptionUtil.encrypt(userId.toString()));
        }
    }


    /**
     * set session username
     *
     * @param session  http session
     * @param username username
     */
    public static void setUsername(HttpSession session, String username) {
        if (username != null) {
            session.setAttribute(USERNAME, username);
        }
    }


    /**
     * set session authentication token
     *
     * @param session   http session
     * @param authToken authentication token
     */
    public static void setAuthToken(HttpSession session, String authToken) throws GeneralSecurityException {
        if (authToken != null && !authToken.trim().equals("")) {
            session.setAttribute(AUTH_TOKEN, EncryptionUtil.encrypt(authToken));
        }
    }

    /**
     * set session timeout
     *
     * @param session http session
     */
    public static void setTimeout(HttpSession session) {
        //set session timeout
        Calendar timeout = Calendar.getInstance();
        timeout.add(Calendar.MINUTE, Integer.parseInt(AppConfig.getProperty("sessionTimeout", "15")));
        session.setAttribute(TIMEOUT, timeoutFormat().format(timeout.getTime()));
    }

    /**
     * SimpleDateFormat is not thread safe, so each caller gets its own.
     */
    private static SimpleDateFormat timeoutFormat() {
        return new SimpleDateFormat(TIMEOUT_FORMAT);
    }

    /**
     * @param session http session
     * @return true if the session has no timeout recorded, or its timeout has passed
     */
    public static boolean isTimedOut(HttpSession session) throws ParseException {
        String timeStr = getTimeout(session);
        if (StringUtils.isEmpty(timeStr)) {
            return true;
        }
        Date sessionTimeout = timeoutFormat().parse(timeStr);
        return sessionTimeout == null || new Date().after(sessionTimeout);
    }

    /**
     * The user type ("M" / "A") this session is authenticated as, or null if it is not
     * authenticated: no auth token, a token AuthDB no longer recognizes, or a session that
     * has timed out.
     * <p>
     * Shared by AuthFilter, which enforces this for /admin/* and /manage/*, and by
     * SecureShellWS, which has to repeat the check because the container does not run
     * filters against a WebSocket upgrade request. Both had their own copy of the token
     * lookup, the AuthDB call and the timeout parsing, which is the last place in this
     * codebase that should be maintained twice - a fix or a tightening applied to one copy
     * silently left the terminal WebSocket, or every admin page, on the old behavior.
     * <p>
     * Does not refresh the timeout; a caller that should extend the session on activity
     * (AuthFilter does, the WebSocket deliberately does not) calls {@link #setTimeout} itself.
     *
     * @param session http session
     * @return the authenticated user type, or null
     */
    public static String authenticatedUserType(HttpSession session)
            throws SQLException, GeneralSecurityException, ParseException {
        if (session == null) {
            return null;
        }
        String authToken = getAuthToken(session);
        if (StringUtils.isEmpty(authToken)) {
            return null;
        }
        String userType = AuthDB.isAuthorized(getUserId(session), authToken);
        if (userType == null) {
            return null;
        }
        return isTimedOut(session) ? null : userType;
    }


    /**
     * delete all session information
     *
     * @param session
     */
    public static void deleteAllSession(HttpSession session) {

        session.setAttribute(TIMEOUT, null);
        session.setAttribute(AUTH_TOKEN, null);
        session.setAttribute(USER_ID, null);
        session.setAttribute(SESSION_ID, null);

        session.invalidate();
    }

    /**
     * return client ip from servlet request
     *
     * @param servletRequest http servlet request
     * @return client ip
     */
    public static String getClientIPAddress(HttpServletRequest servletRequest) {
        String clientIP = null;
        if (StringUtils.isNotEmpty(AppConfig.getProperty("clientIPHeader"))) {
            clientIP = firstForwardedAddress(servletRequest.getHeader(AppConfig.getProperty("clientIPHeader")));
        }
        if (StringUtils.isEmpty(clientIP)) {
            clientIP = servletRequest.getRemoteAddr();
        }
        return clientIP;
    }

    /**
     * The first address in a forwarded-for style header, or null if it is absent or is not a
     * bare IP address.
     * <p>
     * X-Forwarded-For is a comma-separated list that each hop appends to, so even behind a
     * trusted proxy the raw value is "&lt;client&gt;, &lt;proxy&gt;" with a client-supplied
     * prefix. Returning it whole made it useless as a throttle key - any value the client
     * varied produced a brand new key, so ten failures per IP became ten failures per
     * request, and the map in LoginThrottleUtil grew an entry for each one. Taking just the
     * first address and requiring it to parse as an IP also keeps arbitrary header text out
     * of the audit log.
     */
    static String firstForwardedAddress(String headerValue) {
        if (StringUtils.isEmpty(headerValue)) {
            return null;
        }
        String first = StringUtils.substringBefore(headerValue, ",").trim();
        // IPv6 addresses are sometimes bracketed, optionally with a port: [::1]:443
        if (first.startsWith("[")) {
            first = StringUtils.substringBetween(first, "[", "]");
            if (first == null) {
                return null;
            }
        }
        return isLiteralIpAddress(first) ? first : null;
    }

    /**
     * True for a bare IPv4 or IPv6 literal. Deliberately not {@code InetAddress.getByName},
     * which would treat anything unrecognized as a hostname and try to resolve it - a DNS
     * lookup driven by a request header on every login attempt.
     */
    private static boolean isLiteralIpAddress(String value) {
        if (StringUtils.isEmpty(value) || value.length() > MAX_IP_LITERAL_LENGTH) {
            return false;
        }
        return IPV4.matcher(value).matches() || IPV6.matcher(value).matches();
    }

}
