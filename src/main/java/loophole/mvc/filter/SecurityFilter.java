/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.filter;

import java.io.IOException;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Framework-level response headers.
 * <p>
 * Deliberately limited to headers that need no application configuration, so this package
 * stays independent of anything under io.bastillion. The headers that are a policy decision
 * for the deployment - Content-Security-Policy and Strict-Transport-Security - belong to
 * {@code io.bastillion.common.filter.SecurityHeadersFilter}, which is mapped to the same
 * /* path and can read them from the application config.
 */
@WebFilter(urlPatterns = {"/*"})
public class SecurityFilter implements Filter {

    // csrf parameter and session name
    public static final String _CSRF = "_csrf";

    // disable MIME sniffing
    private static final String X_CONTENT_TYPE_HEADER = "X-Content-Type-Options";
    private static final String X_CONTENT_TYPE_VALUE = "nosniff";

    public void init(FilterConfig filterConfig) {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        // setHeader, not addHeader: a header this filter owns should replace any earlier
        // value rather than appear twice. For Strict-Transport-Security in particular a
        // duplicate is not merely untidy - RFC 6797 section 8.1 requires a UA that receives
        // more than one to ignore all of them, silently disabling HSTS.
        httpServletResponse.setHeader(X_CONTENT_TYPE_HEADER, X_CONTENT_TYPE_VALUE);

        // X-XSS-Protection is deliberately not set. It drove the XSS Auditor / XSS Filter,
        // which Chrome removed in 2019 and Edge before it, and which Firefox and Safari never
        // implemented - so no current browser acts on it. While it was live, "1; mode=block"
        // was itself exploitable as a way to selectively disable scripts on a page and as a
        // cross-site information leak, which is why the auditors were withdrawn rather than
        // fixed. The Content-Security-Policy set by SecurityHeadersFilter is what actually
        // constrains script execution now.

        filterChain.doFilter(request, response);

    }

    public void destroy() {
    }
}
