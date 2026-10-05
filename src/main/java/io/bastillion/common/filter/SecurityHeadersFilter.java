/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.filter;

import io.bastillion.common.util.AppConfig;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Sets the hardening response headers that are a policy decision for the deployment, and so
 * need the application config: Content-Security-Policy and Strict-Transport-Security.
 * <p>
 * The lmvc framework's own {@code loophole.mvc.filter.SecurityFilter} is mapped to the same
 * /* path and sets only X-Content-Type-Options, which takes no configuration. Each header has
 * exactly one owner and every one of them is set with setHeader rather than addHeader: per
 * RFC 6797 section 8.1 a UA that receives more than one Strict-Transport-Security header must
 * ignore all of them, so a duplicate would silently disable HSTS entirely.
 * <p>
 * The app's templates rely on inline &lt;script&gt;/&lt;style&gt; blocks (Thymeleaf-injected
 * CSRF tokens, per-user terminal theme colors), so script-src/style-src allow 'unsafe-inline'
 * rather than blocking them outright.
 */
public class SecurityHeadersFilter implements Filter {

    private static final String CSP =
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self'; " +
            "font-src 'self'; " +
            // The terminal WebSocket is same-origin. A bare wss: source would permit a
            // connection to every secure WebSocket host, which is broader than needed.
            "connect-src 'self'; " +
            "object-src 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'; " +
            "frame-ancestors 'self'";

    /**
     * Strict-Transport-Security, built once from config.
     * <p>
     * {@code includeSubDomains} is off by default even though it is the stronger setting,
     * because it is not a reversible mistake: it applies to every subdomain of whatever host
     * served the header, for the whole max-age, and a browser that has cached it will refuse
     * plain HTTP to those names for a year. On a host like bastillion.example.com that
     * affects essentially nothing and is worth turning on; served from an apex domain it
     * would force HTTPS across every sibling subdomain. {@code preload} additionally means
     * asking for the name to be built into browsers, which is harder still to undo, and the
     * preload list requires includeSubDomains - so it is only honored together with it.
     */
    private static final String TRANSPORT_SECURITY_HEADER = "Strict-Transport-Security";
    private static final String TRANSPORT_SECURITY_VALUE = buildTransportSecurityValue();

    private static String buildTransportSecurityValue() {
        StringBuilder value = new StringBuilder("max-age=")
                .append(AppConfig.getProperty("hstsMaxAge", "31536000"));
        if ("true".equals(AppConfig.getProperty("hstsIncludeSubDomains", "false"))) {
            value.append("; includeSubDomains");
            if ("true".equals(AppConfig.getProperty("hstsPreload", "false"))) {
                value.append("; preload");
            }
        }
        return value.toString();
    }

    public void init(FilterConfig config) {
    }

    public void destroy() {
    }

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) resp;

        response.setHeader("Content-Security-Policy", CSP);
        response.setHeader(TRANSPORT_SECURITY_HEADER, TRANSPORT_SECURITY_VALUE);
        response.setHeader("X-Frame-Options", "SAMEORIGIN");
        response.setHeader("Referrer-Policy", "same-origin");

        chain.doFilter(req, resp);
    }
}
