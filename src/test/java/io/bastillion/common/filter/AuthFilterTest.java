/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.filter;

import io.bastillion.common.util.AuthTestSupport;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.model.Auth;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.SQLException;

import static io.bastillion.common.util.AuthTestSupport.encryptedAttribute;
import static io.bastillion.common.util.AuthTestSupport.timeoutString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AuthFilter is the gate in front of every /manage/* request - these tests exercise the
 * privilege-boundary decisions directly (MANAGER vs. ADMINISTRATOR vs. /manage/ paths,
 * session timeout, an auth token AuthDB no longer recognizes) since that logic has no other
 * automated coverage.
 */
@ExtendWith(MockitoExtension.class)
class AuthFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private FilterChain filterChain;

    private final AuthFilter filter = new AuthFilter();

    // Timeout is only stubbed by callers that expect AuthFilter to actually reach the
    // timeout check - AuthDB.isAuthorized returning null/throwing short-circuits before that
    // point, and Mockito's strict stubs flag an unread stub as an error.
    private void givenAuthenticatedSession(String authToken, long userId) throws Exception {
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(AuthUtil.AUTH_TOKEN)).thenReturn(encryptedAttribute(authToken));
        when(session.getAttribute(AuthUtil.USER_ID)).thenReturn(encryptedAttribute(String.valueOf(userId)));
    }

    @Test
    void noAuthTokenRedirectsToLoginWithoutContinuingChain() throws Exception {
        when(request.getSession()).thenReturn(session);
        when(request.getContextPath()).thenReturn("");

        filter.doFilter(request, response, filterChain);

        verify(response).sendRedirect("/");
        verify(filterChain, never()).doFilter(any(), any());
        verify(session).invalidate();
    }

    @Test
    void validManagerTokenContinuesChainRegardlessOfPath() throws Exception {
        givenAuthenticatedSession("token123", 5L);
        when(session.getAttribute(AuthUtil.TIMEOUT)).thenReturn(timeoutString(10));
        when(request.getServletPath()).thenReturn("/manage/systems");

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.isAuthorized(5L, "token123")).thenReturn(Auth.MANAGER);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(response, never()).sendRedirect(any());
        }
    }

    @Test
    void administratorIsBlockedFromManagePaths() throws Exception {
        givenAuthenticatedSession("token123", 5L);
        when(session.getAttribute(AuthUtil.TIMEOUT)).thenReturn(timeoutString(10));
        when(request.getServletPath()).thenReturn("/manage/systems");
        when(request.getContextPath()).thenReturn("");

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.isAuthorized(5L, "token123")).thenReturn(Auth.ADMINISTRATOR);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(any(), any());
            verify(response).sendRedirect("/");
        }
    }

    @Test
    void administratorCanReachNonManagePaths() throws Exception {
        givenAuthenticatedSession("token123", 5L);
        when(session.getAttribute(AuthUtil.TIMEOUT)).thenReturn(timeoutString(10));
        when(request.getServletPath()).thenReturn("/dashboard");

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.isAuthorized(5L, "token123")).thenReturn(Auth.ADMINISTRATOR);

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(response, never()).sendRedirect(any());
        }
    }

    @Test
    void expiredSessionRedirectsDespiteAnOtherwiseValidToken() throws Exception {
        givenAuthenticatedSession("token123", 5L);
        when(session.getAttribute(AuthUtil.TIMEOUT)).thenReturn(timeoutString(-10));
        // No getServletPath() stub: an expired session is rejected before the requested path
        // is looked at, so which path it was never enters into it.
        when(request.getContextPath()).thenReturn("");

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.isAuthorized(5L, "token123")).thenReturn(Auth.MANAGER);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(any(), any());
            verify(response).sendRedirect("/");
            verify(session).invalidate();
        }
    }

    @Test
    void tokenAuthDbNoLongerRecognizesRedirects() throws Exception {
        givenAuthenticatedSession("stale-token", 5L);
        when(request.getContextPath()).thenReturn("");

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.isAuthorized(5L, "stale-token")).thenReturn(null);

            filter.doFilter(request, response, filterChain);

            verify(filterChain, never()).doFilter(any(), any());
            verify(response).sendRedirect("/");
        }
    }

    @Test
    void dbFailureFailsClosedAndClearsSession() throws Exception {
        givenAuthenticatedSession("token123", 5L);

        try (MockedStatic<AuthDB> authDB = mockStatic(AuthDB.class)) {
            authDB.when(() -> AuthDB.isAuthorized(anyLong(), eq("token123")))
                    .thenThrow(new SQLException("connection lost"));

            ServletException exception = assertThrows(ServletException.class,
                    () -> filter.doFilter(request, response, filterChain));

            assertEquals("Request processing failed", exception.getMessage());
            assertNull(exception.getCause());

            verify(filterChain, never()).doFilter(any(), any());
            verify(session).invalidate();
        }
    }
}
