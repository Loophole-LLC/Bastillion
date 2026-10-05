package io.bastillion.common.filter;

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
class SecurityHeadersFilterTest {

    @Mock
    private ServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    @Test
    void restrictsConnectionsToTheSameOriginAndAddsHardeningHeaders() throws Exception {
        new SecurityHeadersFilter().doFilter(request, response, chain);

        verify(response).setHeader("Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                        + "style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; "
                        + "connect-src 'self'; object-src 'none'; base-uri 'self'; "
                        + "form-action 'self'; frame-ancestors 'self'");
        verify(response).setHeader("X-Frame-Options", "SAMEORIGIN");
        verify(response).setHeader("Referrer-Policy", "same-origin");
        verify(chain).doFilter(request, response);
    }

    @Test
    void setsStrictTransportSecurityExactlyOnce() throws Exception {
        // This filter owns the header; loophole.mvc.filter.SecurityFilter, mapped to the same
        // /* path, must not also set it. RFC 6797 section 8.1 requires a UA that receives more
        // than one Strict-Transport-Security header to ignore all of them, so a duplicate does
        // not merely repeat the policy - it turns HSTS off.
        new SecurityHeadersFilter().doFilter(request, response, chain);

        // includeSubDomains and preload are opt-in (hstsIncludeSubDomains / hstsPreload),
        // since a browser that cached them refuses plain HTTP to those names for the whole
        // max-age - not a mistake that can be taken back.
        verify(response).setHeader("Strict-Transport-Security", "max-age=31536000");
        verify(response, never()).addHeader(eq("Strict-Transport-Security"), anyString());
    }
}
