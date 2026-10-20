/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.saml;

import io.bastillion.common.util.AuthSessionUtil;
import io.bastillion.manage.model.User;
import io.bastillion.manage.util.ExternalAuthException;
import io.bastillion.manage.util.SamlAuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * doPost() is the one place that decides where a SAML login attempt ends up - these tests
 * pin down every AuthSessionUtil.Status branch's redirect target. It's package-private
 * (protected on HttpServlet), and this test lives in the same package deliberately so it can
 * call it directly rather than going through a full servlet-container request dispatch.
 */
@ExtendWith(MockitoExtension.class)
class SamlAcsServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private final SamlAcsServlet servlet = new SamlAcsServlet();

    private static User namedUser() {
        User user = new User();
        user.setUsername("alice");
        return user;
    }

    private void stubContextPath() {
        when(request.getContextPath()).thenReturn("");
    }

    @Test
    void invalidAssertionRedirectsToLoginWithInvalidSsoError() throws Exception {
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn(null);

            servlet.doPost(request, response);

            verify(response).sendRedirect("/login.ktrl?ssoError=invalid");
        }
    }

    @Test
    void unloadableSamlSettingsRedirectsWithUnavailableSsoError() throws Exception {
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request))
                    .thenThrow(new ExternalAuthException("SAML settings could not be loaded"));

            servlet.doPost(request, response);

            verify(response).sendRedirect("/login.ktrl?ssoError=unavailable");
        }
    }

    @Test
    void successRedirectsToMenu() throws Exception {
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class);
             MockedStatic<AuthSessionUtil> authSessionUtil = mockStatic(AuthSessionUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn("tok-123");
            authSessionUtil.when(() -> AuthSessionUtil.establishSession(request, response, "tok-123", null, true))
                    .thenReturn(new AuthSessionUtil.Result(AuthSessionUtil.Status.SUCCESS, namedUser()));

            servlet.doPost(request, response);

            verify(response).sendRedirect("/admin/menu.html");
        }
    }

    @Test
    void firstTimeOtpEnrollmentRedirectsToOtpSetup() throws Exception {
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class);
             MockedStatic<AuthSessionUtil> authSessionUtil = mockStatic(AuthSessionUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn("tok-123");
            authSessionUtil.when(() -> AuthSessionUtil.establishSession(request, response, "tok-123", null, true))
                    .thenReturn(new AuthSessionUtil.Result(AuthSessionUtil.Status.OTP_ENROLLMENT_REQUIRED, namedUser()));

            servlet.doPost(request, response);

            verify(response).sendRedirect("/admin/viewOTP.ktrl");
        }
    }

    @Test
    void noProfilesRedirectsToLoginWithNoprofileSsoError() throws Exception {
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class);
             MockedStatic<AuthSessionUtil> authSessionUtil = mockStatic(AuthSessionUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn("tok-123");
            authSessionUtil.when(() -> AuthSessionUtil.establishSession(request, response, "tok-123", null, true))
                    .thenReturn(new AuthSessionUtil.Result(AuthSessionUtil.Status.NO_PROFILES, namedUser()));

            servlet.doPost(request, response);

            verify(response).sendRedirect("/login.ktrl?ssoError=noprofile");
        }
    }

    @Test
    void expiredAccountRedirectsToLoginWithExpiredSsoError() throws Exception {
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class);
             MockedStatic<AuthSessionUtil> authSessionUtil = mockStatic(AuthSessionUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn("tok-123");
            authSessionUtil.when(() -> AuthSessionUtil.establishSession(request, response, "tok-123", null, true))
                    .thenReturn(new AuthSessionUtil.Result(AuthSessionUtil.Status.EXPIRED, namedUser()));

            servlet.doPost(request, response);

            verify(response).sendRedirect("/login.ktrl?ssoError=expired");
        }
    }

    @Test
    void aFreshSessionIsForcedOnEveryResponseEvenOnFailure() throws Exception {
        // Regression test, take two: an SP-initiated login always starts with a normal
        // same-origin GET to /login.html, which already put an ordinary _csrf-bearing session
        // cookie in the browser's jar before the user ever clicks "Sign in with SSO". The
        // first fix attempt tried invalidating request.getSession(false) here, but that's
        // always null on this request - the IdP's POST is cross-origin, so SameSite=Lax has
        // already stripped that old cookie from what this servlet can see; there was nothing
        // on the request side to invalidate. The actual fix has to act on the *response*:
        // force getSession(true) unconditionally so a fresh Set-Cookie always goes out,
        // which overwrites the browser's stale cookie by construction regardless of what the
        // incoming (cookie-less) request could see. Verified for real by driving a real
        // browser through a real Entra tenant - the first fix compiled, passed every existing
        // test, and still didn't work; only re-testing against the real IdP caught it.
        stubContextPath();
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn(null);

            servlet.doPost(request, response);

            verify(request).getSession(true);
        }
    }

    @Test
    void contextPathIsPrependedToEveryRedirect() throws Exception {
        when(request.getContextPath()).thenReturn("/bastillion");
        try (MockedStatic<SamlAuthUtil> samlAuthUtil = mockStatic(SamlAuthUtil.class)) {
            samlAuthUtil.when(() -> SamlAuthUtil.login(request)).thenReturn(null);

            servlet.doPost(request, response);

            verify(response).sendRedirect("/bastillion/login.ktrl?ssoError=invalid");
        }
    }
}
