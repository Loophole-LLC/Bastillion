/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.filter;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.util.HostKeyAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.text.ParseException;

/**
 * Filter determines if admin user is authenticated
 */
public class AuthFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    /**
     * Request attribute holding the number of host keys currently refusing connections, read
     * by the navigation fragment to badge the Host Keys link.
     */
    public static final String BLOCKED_HOST_KEYS = "blockedHostKeyCount";

    public void init(FilterConfig config) throws ServletException {

    }

    public void destroy() {
    }

    /**
     * doFilter determines if user is an administrator or redirect to login page
     *
     * @param req   task request
     * @param resp  task response
     * @param chain filter chain
     * @throws ServletException
     */
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws ServletException {


        HttpServletRequest servletRequest = (HttpServletRequest) req;
        HttpServletResponse servletResponse = (HttpServletResponse) resp;
        boolean isAdmin = false;

        try {
            //valid, non-expired auth token for a known user, or null
            String userType = AuthUtil.authenticatedUserType(servletRequest.getSession());

            if (userType != null) {
                // Normalized servlet path, not the raw request URI - see BaseKontroller.execute()
                // for why raw getRequestURI() + contains() is unsafe for path-based auth decisions.
                String uri = servletRequest.getServletPath();
                if (Auth.MANAGER.equals(userType)) {
                    isAdmin = true;
                } else if (!uri.contains("/manage/") && Auth.ADMINISTRATOR.equals(userType)) {
                    isAdmin = true;
                }
                AuthUtil.setUserType(servletRequest.getSession(), userType);
                //extend the window on activity
                AuthUtil.setTimeout(servletRequest.getSession());

                // Published here rather than read from the navigation fragment directly:
                // Thymeleaf 3.1 restricts calling static methods from expressions (static
                // fields, as the fragment uses elsewhere, are still fine), and a template
                // reaching into the data layer for a live count is the wrong shape anyway.
                // Managers only - nobody else can act on it. HostKeyAlert caches, so this is
                // not a query per request.
                if (Auth.MANAGER.equals(userType)) {
                    servletRequest.setAttribute(BLOCKED_HOST_KEYS, HostKeyAlert.blockingCount());
                }
            }

            //if not admin redirect to login page
            if (!isAdmin) {
                AuthUtil.deleteAllSession(servletRequest.getSession());
                servletResponse.sendRedirect(servletRequest.getContextPath() + "/");
            } else {
                chain.doFilter(req, resp);
            }
        } catch (SQLException | ParseException | IOException | GeneralSecurityException ex) {
            AuthUtil.deleteAllSession(servletRequest.getSession());
            log.error(ex.toString(), ex);
            throw new ServletException("Request processing failed");
        }
    }
}
