/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.base;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import loophole.mvc.filter.SecurityFilter;
import loophole.mvc.testctrl.DummyController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DispatcherServletTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private RequestDispatcher dispatcher;

    private final DispatcherServlet servlet = new DispatcherServlet();

    @BeforeEach
    void setUp() {
        DummyController.reset();
        lenient().when(request.getParameterNames()).thenReturn(Collections.emptyEnumeration());
    }

    @Test
    void forwardsToViewReturnedByController() throws Exception {
        when(request.getServletPath()).thenReturn("/hello.ktrl");
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestDispatcher("/hello.html")).thenReturn(dispatcher);

        servlet.doGet(request, response);

        verify(dispatcher).forward(request, response);
    }

    @Test
    void redirectsAndAppendsCsrfTokenFromSession() throws Exception {
        when(request.getServletPath()).thenReturn("/redirect.ktrl");
        when(request.getMethod()).thenReturn("GET");
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(SecurityFilter._CSRF)).thenReturn("TOKEN123");
        when(request.getContextPath()).thenReturn("/app");

        servlet.doGet(request, response);

        verify(response).sendRedirect("/app/target?_csrf=TOKEN123");
    }

    @Test
    void unmatchedUriWithNothingWrittenYetSends404() throws Exception {
        // No route is registered for this servlet path, so BaseKontroller.execute() returns
        // a null forward and the servlet falls through to sendError().
        when(request.getServletPath()).thenReturn("/doesNotExist.ktrl");
        when(request.getMethod()).thenReturn("GET");
        when(response.isCommitted()).thenReturn(false);

        servlet.doGet(request, response);

        verify(response).sendError(HttpServletResponse.SC_NOT_FOUND);
    }

    @Test
    void unmatchedForwardOnAnAlreadyCommittedResponseDoesNotAttemptSendError() throws Exception {
        // Mirrors OTPKtrl.qrImage()/AuthKeysKtrl.downloadPvtKey()/
        // SessionAuditKtrl.streamTermOutputForSession(): the controller writes and closes
        // the response body itself and returns null on success - sendError() on an
        // already-committed response throws IllegalStateException("COMPLETED") in Jetty, even
        // though the response was already sent to the client successfully.
        when(request.getServletPath()).thenReturn("/doesNotExist.ktrl");
        when(request.getMethod()).thenReturn("GET");
        when(response.isCommitted()).thenReturn(true);

        servlet.doGet(request, response);

        verify(response, never()).sendError(anyInt());
    }
}
