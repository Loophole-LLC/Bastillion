/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CSRFFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private FilterChain filterChain;

    private final CSRFFilter filter = new CSRFFilter();

    @Test
    void firstRequestWithNoSessionTokenIssuesNewTokenAndContinuesChain() throws Exception {
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(session).setAttribute(org.mockito.ArgumentMatchers.eq(SecurityFilter._CSRF), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void getRequestWithMatchingTokenContinuesChainWithoutRotatingToken() throws Exception {
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getParameter(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getMethod()).thenReturn("GET");

        filter.doFilter(request, response, filterChain);

        verify(session, never()).setAttribute(org.mockito.ArgumentMatchers.eq(SecurityFilter._CSRF), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void postRequestWithMatchingTokenRotatesTokenAndContinuesChain() throws Exception {
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getParameter(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getMethod()).thenReturn("POST");

        filter.doFilter(request, response, filterChain);

        verify(session).setAttribute(org.mockito.ArgumentMatchers.eq(SecurityFilter._CSRF), any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void mismatchedTokenRedirectsWithoutContinuingChain() throws Exception {
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getParameter(SecurityFilter._CSRF)).thenReturn("WRONG");
        when(request.getContextPath()).thenReturn("/app");

        filter.doFilter(request, response, filterChain);

        verify(response).sendRedirect("/app/");
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void mismatchedTokenDoesNotInvalidateTheSession() throws Exception {
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getParameter(SecurityFilter._CSRF)).thenReturn("WRONG");
        when(request.getContextPath()).thenReturn("/app");

        filter.doFilter(request, response, filterChain);

        verify(session, never()).invalidate();
    }

    @Test
    void requestWithNoTokenParameterAtAllDoesNotInvalidateTheSession() throws Exception {
        // The shape that made this a one-tag logout for any third-party page: the filter also
        // covers plain page GETs (*.html), and an absent _csrf parameter fails the comparison
        // exactly like a wrong one. <img src="https://host/admin/menu.html"> on an unrelated
        // site therefore used to destroy the session of every signed-in user who loaded it,
        // with no token knowledge needed. The request must still be refused.
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getParameter(SecurityFilter._CSRF)).thenReturn(null);
        when(request.getContextPath()).thenReturn("/app");

        filter.doFilter(request, response, filterChain);

        verify(session, never()).invalidate();
        verify(filterChain, never()).doFilter(any(), any());
    }
}
