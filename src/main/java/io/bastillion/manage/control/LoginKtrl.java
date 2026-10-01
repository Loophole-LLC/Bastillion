/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.saml.SamlSettingsUtil;
import io.bastillion.common.util.AppConfig;
import io.bastillion.common.util.AuthSessionUtil;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.common.util.LoginThrottleUtil;
import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.util.SamlAuthUtil;
import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
import loophole.mvc.annotation.Validate;
import loophole.mvc.base.BaseKontroller;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class LoginKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(LoginKtrl.class);

    //check if otp is enabled
    @Model(name = "otpEnabled")
    static final Boolean otpEnabled = ("required".equals(AppConfig.getProperty("oneTimePassword")) || "optional".equals(AppConfig.getProperty("oneTimePassword")));
    //check if SAML SSO is enabled
    @Model(name = "samlEnabled")
    static final Boolean samlEnabled = SamlAuthUtil.samlAuthEnabled;
    private static final Logger loginAuditLogger = LoggerFactory.getLogger("io.bastillion.manage.control.LoginAudit");
    private final String AUTH_ERROR = "Authentication Failed : Login credentials are invalid";
    private final String AUTH_ERROR_NO_PROFILE = "Authentication Failed : There are no profiles assigned to this account";
    private final String AUTH_ERROR_EXPIRED_ACCOUNT = "Authentication Failed : Account has expired";
    private final String SSO_ERROR = "Authentication Failed : Single sign-on login was not successful";
    @Model(name = "auth")
    Auth auth;
    //bound from the ?ssoError= query param SamlAcsServlet redirects failures to - see
    //loophole.mvc.base.BaseKontroller's generic request-param field binding
    String ssoError;


    public LoginKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/login", method = MethodType.GET)
    public String login() {
        if (ssoError != null) {
            switch (ssoError) {
                case "noprofile" -> addError(AUTH_ERROR_NO_PROFILE);
                case "expired" -> addError(AUTH_ERROR_EXPIRED_ACCOUNT);
                default -> addError(SSO_ERROR);
            }
        }
        return "/login.html";
    }

    /**
     * Redirects the browser to the IdP to start an SP-initiated SAML SSO login. A same-origin
     * GET click, so this is an ordinary @Kontrol method (unlike SamlAcsServlet, which handles
     * the IdP's cross-origin POST back and can't be one - see its class javadoc).
     */
    @Kontrol(path = "/samlLogin", method = MethodType.GET)
    public String samlLogin() {
        if (!samlEnabled) {
            return "redirect:/";
        }
        try {
            String redirectUrl = SamlSettingsUtil.buildLoginRedirectUrl(SamlSettingsUtil.getSettings());
            //writes the response directly rather than returning "redirect:" + redirectUrl -
            //DispatcherServlet auto-appends Bastillion's own _csrf param to any "redirect:"
            //return value, which is meaningless (and wrong) for a redirect to a third-party
            //IdP URL. Returning null after writing the response directly is an established
            //pattern here - see OTPKtrl.qrImage, AuthKeysKtrl.downloadPvtKey.
            getResponse().sendRedirect(redirectUrl);
        } catch (Exception ex) {
            log.error(ex.toString(), ex);
            return "redirect:/login.ktrl?ssoError=invalid";
        }
        return null;
    }

    private static final String AUTH_ERROR_TOO_MANY_ATTEMPTS = "Authentication Failed : Too many failed login attempts. Please try again later.";

    @Kontrol(path = "/loginSubmit", method = MethodType.POST)
    public String loginSubmit() throws ServletException {
        String retVal = "redirect:/admin/menu.html";

        //get client IP
        String clientIP = AuthUtil.getClientIPAddress(getRequest());

        //throttle by client IP, not by username - a per-account lockout would let anyone
        //remotely lock out a known admin username by deliberately failing its password
        if (LoginThrottleUtil.isBlocked(clientIP)) {
            loginAuditLogger.info(auth.getUsername() + " (" + clientIP + ") - " + AUTH_ERROR_TOO_MANY_ATTEMPTS);
            addError(AUTH_ERROR_TOO_MANY_ATTEMPTS);
            return "/login.html";
        }

        String authToken = null;
        try {
            authToken = AuthDB.login(auth);

            if (authToken != null) {

                AuthSessionUtil.Result result = AuthSessionUtil.establishSession(
                        getRequest(), getResponse(), authToken, auth.getOtpToken(), false);

                switch (result.status()) {
                    case NOT_FOUND, OTP_INVALID -> {
                        LoginThrottleUtil.recordFailure(clientIP);
                        loginAuditLogger.info(auth.getUsername() + " (" + clientIP + ") - " + AUTH_ERROR);
                        addError(AUTH_ERROR);
                        return "/login.html";
                    }
                    case NO_PROFILES -> {
                        loginAuditLogger.info(auth.getUsername() + " (" + clientIP + ") - " + AUTH_ERROR_NO_PROFILE);
                        addError(AUTH_ERROR_NO_PROFILE);
                        return "/login.html";
                    }
                    case EXPIRED -> {
                        loginAuditLogger.info(auth.getUsername() + " (" + clientIP + ") - " + AUTH_ERROR_EXPIRED_ACCOUNT);
                        addError(AUTH_ERROR_EXPIRED_ACCOUNT);
                        return "/login.html";
                    }
                    case OTP_ENROLLMENT_REQUIRED -> retVal = "redirect:/admin/viewOTP.ktrl";
                    case SUCCESS -> retVal = "changeme".equals(auth.getPassword())
                            && Auth.AUTH_BASIC.equals(result.user().getAuthType())
                            ? "redirect:/admin/userSettings.ktrl?defaultPassword=true" : "redirect:/admin/menu.html";
                }
                LoginThrottleUtil.recordSuccess(clientIP);
                loginAuditLogger.info(auth.getUsername() + " (" + clientIP + ") - Authentication Success");

            } else {
                LoginThrottleUtil.recordFailure(clientIP);
                loginAuditLogger.info(auth.getUsername() + " (" + clientIP + ") - " + AUTH_ERROR);
                addError(AUTH_ERROR);
                retVal = "/login.html";
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }


        return retVal;
    }


    @Kontrol(path = "/logout", method = MethodType.GET)
    public String logout() {
        AuthUtil.deleteAllSession(getRequest().getSession());
        return "redirect:/";
    }


    /**
     * Validates fields for auth submit
     */
    @Validate(input = "/login.html")
    public void validateLoginSubmit() {
        if (auth.getUsername() == null ||
                auth.getUsername().trim().equals("")) {
            addFieldError("auth.username", "Required");
        }
        if (auth.getPassword() == null ||
                auth.getPassword().trim().equals("")) {
            addFieldError("auth.password", "Required");
        }

    }
}
