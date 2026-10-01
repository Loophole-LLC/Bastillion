/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.common.util.LoginThrottleUtil;
import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * loginSubmit() is the actual credential/OTP/profile/expiry gate in front of the whole app -
 * every branch here decides whether a session gets created. otpEnabled is a static field
 * baked in at class-load time from the bundled default (oneTimePassword=optional), so it's
 * true for the whole test JVM; these tests work with that rather than trying to flip it.
 */
@ExtendWith(MockitoExtension.class)
class LoginKtrlTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private static void setAuth(LoginKtrl ktrl, Auth auth) throws Exception {
        Field field = LoginKtrl.class.getDeclaredField("auth");
        field.setAccessible(true);
        field.set(ktrl, auth);
    }

    private static long validOtpTokenFor(String base32Secret) throws Exception {
        byte[] key = new org.apache.commons.codec.binary.Base32().decode(base32Secret);
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        long step = System.currentTimeMillis() / 30000;
        byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
        int offset = hash[hash.length - 1] & 0xF;
        long calculated = 0;
        for (int i = 0; i < 4; i++) {
            calculated <<= 8;
            calculated |= (hash[offset + i] & 0xFF);
        }
        return (calculated & 0x7FFFFFFF) % 1000000;
    }

    private static User managerWithProfile() {
        User user = new User();
        user.setId(1L);
        user.setUsername("alice");
        user.setUserType(Auth.MANAGER);
        user.setAuthType(Auth.AUTH_BASIC);
        return user;
    }

    // lenient: several rejection-path tests return before loginSubmit() ever touches the
    // session, so this stub goes unused there - same shared-setup situation as
    // DispatcherServletTest's lenient() getParameterNames() stub.
    private LoginKtrl newController() {
        LoginKtrl ktrl = new LoginKtrl(request, response);
        lenient().when(request.getSession()).thenReturn(session);
        return ktrl;
    }

    private static String freshIp() {
        return "198.51.100." + UUID.randomUUID().toString().substring(0, 8);
    }

    // ---- per-IP login throttle (LoginThrottleUtil) ---------------------------------------
    // getClientIPAddress() falls back to request.getRemoteAddr(), unstubbed (null) in every
    // other test in this file - LoginThrottleUtil.isBlocked(null) is always false, which is
    // exactly why those tests never interact with throttling at all. These stub a real,
    // unique-per-test IP instead so the shared static throttle state can't leak between tests.

    @Test
    void throttledIpIsRejectedBeforeAuthDbIsEverConsulted() throws Exception {
        String ip = freshIp();
        when(request.getRemoteAddr()).thenReturn(ip);
        for (int i = 0; i < 10; i++) {
            LoginThrottleUtil.recordFailure(ip);
        }

        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("whatever-the-real-password-is");
        setAuth(ktrl, auth);

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            String view = ktrl.loginSubmit();

            assertEquals("/login.html", view);
            assertTrue(ktrl.getErrors().contains(
                    "Authentication Failed : Too many failed login attempts. Please try again later."));
            authDB.verify(() -> AuthDB.login(any()), never());
        }
    }

    @Test
    void invalidCredentialsShowsGenericAuthErrorAndDoesNotCreateASession() throws Exception {
        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("wrong");
        setAuth(ktrl, auth);

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn(null);

            String view = ktrl.loginSubmit();

            assertEquals("/login.html", view);
            assertTrue(ktrl.getErrors().contains(
                    "Authentication Failed : Login credentials are invalid"));
            verify(session, never()).setAttribute(eq(AuthUtil.AUTH_TOKEN), any());
        }
    }

    @Test
    void wrongOtpTokenRejectsLoginEvenWithCorrectPassword() throws Exception {
        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("correct");
        auth.setOtpToken(1L);
        setAuth(ktrl, auth);

        User user = managerWithProfile();

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-123");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-123")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(1L)).thenReturn("JBSWY3DPEHPK3PXP");

            String view = ktrl.loginSubmit();

            assertEquals("/login.html", view);
            assertTrue(ktrl.getErrors().contains(
                    "Authentication Failed : Login credentials are invalid"));
            verify(session, never()).setAttribute(eq(AuthUtil.AUTH_TOKEN), any());
        }
    }

    @Test
    void correctOtpTokenCompletesLoginAndCreatesASession() throws Exception {
        LoginKtrl ktrl = newController();
        String secret = "JBSWY3DPEHPK3PXP";
        long validToken = validOtpTokenFor(secret);

        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("correct");
        auth.setOtpToken(validToken);
        setAuth(ktrl, auth);

        User user = managerWithProfile();
        user.setUiTheme("light");

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-123");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-123")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(1L)).thenReturn(secret);

            String view = ktrl.loginSubmit();

            assertEquals("redirect:/admin/menu.html", view);
            verify(session).setAttribute(eq(AuthUtil.AUTH_TOKEN), any());
            verify(response).addHeader(eq("Set-Cookie"), contains("bastillion_theme=light"));
            authDB.verify(() -> AuthDB.updateLastLogin(user));
        }
    }

    @Test
    void firstLoginWithNoSharedSecretYetRedirectsToOtpSetup() throws Exception {
        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("correct");
        setAuth(ktrl, auth);

        User user = managerWithProfile();

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-123");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-123")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(1L)).thenReturn(null);

            String view = ktrl.loginSubmit();

            assertEquals("redirect:/admin/viewOTP.ktrl", view);
        }
    }

    @Test
    void defaultChangemePasswordForcesRedirectToUserSettings() throws Exception {
        LoginKtrl ktrl = newController();
        String secret = "JBSWY3DPEHPK3PXP";
        long validToken = validOtpTokenFor(secret);

        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("changeme");
        auth.setOtpToken(validToken);
        setAuth(ktrl, auth);

        User user = managerWithProfile();

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-123");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-123")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(1L)).thenReturn(secret);

            String view = ktrl.loginSubmit();

            assertEquals("redirect:/admin/userSettings.ktrl?defaultPassword=true", view);
        }
    }

    @Test
    void administratorWithNoAssignedProfilesIsRejected() throws Exception {
        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("bob");
        auth.setPassword("correct");
        setAuth(ktrl, auth);

        User user = new User();
        user.setId(2L);
        user.setUsername("bob");
        user.setUserType(Auth.ADMINISTRATOR);
        user.setProfileList(Collections.emptyList());

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-456");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-456")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(2L)).thenReturn(null);

            String view = ktrl.loginSubmit();

            assertEquals("/login.html", view);
            assertTrue(ktrl.getErrors().contains(
                    "Authentication Failed : There are no profiles assigned to this account"));
            verify(session, never()).setAttribute(eq(AuthUtil.AUTH_TOKEN), any());
        }
    }

    @Test
    void managerBypassesTheProfileCheck() throws Exception {
        // MANAGER accounts administer the whole app and aren't scoped to profiles - the
        // `!User.MANAGER.equals(userType)` guard exists specifically to exempt them.
        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("correct");
        setAuth(ktrl, auth);

        User user = managerWithProfile();
        user.setProfileList(Collections.emptyList());

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-789");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-789")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(1L)).thenReturn(null);

            String view = ktrl.loginSubmit();

            assertEquals("redirect:/admin/viewOTP.ktrl", view);
        }
    }

    @Test
    void expiredAccountIsRejectedEvenWithCorrectCredentials() throws Exception {
        LoginKtrl ktrl = newController();
        Auth auth = new Auth();
        auth.setUsername("alice");
        auth.setPassword("correct");
        setAuth(ktrl, auth);

        User user = managerWithProfile();
        user.setExpired(true);

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.login(auth)).thenReturn("tok-999");
            authDB.when(() -> AuthDB.getUserByAuthToken("tok-999")).thenReturn(user);
            authDB.when(() -> AuthDB.getSharedSecret(1L)).thenReturn(null);

            String view = ktrl.loginSubmit();

            assertEquals("/login.html", view);
            assertTrue(ktrl.getErrors().contains(
                    "Authentication Failed : Account has expired"));
            verify(session, never()).setAttribute(eq(AuthUtil.AUTH_TOKEN), any());
        }
    }

    @Test
    void logoutClearsSessionAndRedirectsHome() {
        LoginKtrl ktrl = newController();

        String view = ktrl.logout();

        assertEquals("redirect:/", view);
        verify(session).invalidate();
    }

    // ---- ssoError (SamlAcsServlet's failure-path redirect back to /login.ktrl) -----------

    @Test
    void loginWithNoSsoErrorShowsNoErrors() {
        LoginKtrl ktrl = newController();

        String view = ktrl.login();

        assertEquals("/login.html", view);
        assertTrue(ktrl.getErrors().isEmpty());
    }

    @Test
    void loginWithNoProfileSsoErrorShowsTheSameMessageAsLocalLoginsNoProfileRejection() {
        LoginKtrl ktrl = newController();
        ktrl.ssoError = "noprofile";

        String view = ktrl.login();

        assertEquals("/login.html", view);
        assertTrue(ktrl.getErrors().contains(
                "Authentication Failed : There are no profiles assigned to this account"));
    }

    @Test
    void loginWithExpiredSsoErrorShowsTheSameMessageAsLocalLoginsExpiredRejection() {
        LoginKtrl ktrl = newController();
        ktrl.ssoError = "expired";

        String view = ktrl.login();

        assertTrue(ktrl.getErrors().contains("Authentication Failed : Account has expired"));
    }

    @Test
    void loginWithUnrecognizedSsoErrorShowsAGenericSsoMessage() {
        LoginKtrl ktrl = newController();
        ktrl.ssoError = "invalid";

        String view = ktrl.login();

        assertTrue(ktrl.getErrors().contains(
                "Authentication Failed : Single sign-on login was not successful"));
    }
}
