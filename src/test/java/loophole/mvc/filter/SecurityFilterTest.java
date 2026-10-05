/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityFilterTest {

    @Mock
    private ServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private final SecurityFilter filter = new SecurityFilter();

    @Test
    void setsNosniffAndContinuesChain() throws Exception {
        filter.doFilter(request, response, filterChain);

        // setHeader, not addHeader - this filter owns the header and must replace rather
        // than append (see SecurityFilter, and RFC 6797 section 8.1 for why a duplicate is
        // actively harmful in the HSTS case).
        verify(response).setHeader("X-Content-Type-Options", "nosniff");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doesNotSetTheWithdrawnXssProtectionHeader() throws Exception {
        // No current browser acts on X-XSS-Protection: it drove the XSS Auditor / XSS Filter,
        // which Chrome and Edge removed and Firefox and Safari never shipped. While live,
        // "1; mode=block" was itself usable to selectively disable scripts and to leak
        // cross-site information. CSP is what constrains scripts now.
        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("X-XSS-Protection"), anyString());
        verify(response, never()).addHeader(eq("X-XSS-Protection"), anyString());
    }

    @Test
    void leavesTheConfigurableHeadersToTheApplicationFilter() throws Exception {
        // Strict-Transport-Security and Content-Security-Policy are deployment policy and
        // need the app config, so SecurityHeadersFilter owns them - mapped to the same /*
        // path. Setting them in both places is what RFC 6797 section 8.1 punishes.
        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Strict-Transport-Security"), anyString());
        verify(response, never()).addHeader(eq("Strict-Transport-Security"), anyString());
        verify(response, never()).setHeader(eq("Content-Security-Policy"), anyString());
        verify(response, never()).addHeader(eq("Content-Security-Policy"), anyString());
    }
}
