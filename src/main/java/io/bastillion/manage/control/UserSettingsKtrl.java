/**
 * Copyright (C) 2015 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import com.jcraft.jsch.JSchException;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.common.util.ThemeUtil;
import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.db.CertAuthorityDB;
import io.bastillion.manage.db.PrivateKeyDB;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.db.UserThemeDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.model.UserSettings;
import io.bastillion.manage.util.PasswordUtil;
import io.bastillion.manage.util.SSHUtil;
import io.bastillion.manage.util.SshCertificateAuth;
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
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static java.util.Map.entry;

/**
 * Action for user settings
 */
public class UserSettingsKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(UserSettingsKtrl.class);

    public static final String REQUIRED = "Required";
    // Fixed palettes, shared by every request: unmodifiable so neither a controller bug nor
    // a request-parameter bind can mutate the copy every other user is served. The binder in
    // BaseKontroller now refuses static fields outright, which is what previously let
    // ?themeMap['x']=y put an arbitrary entry into this map for everyone, permanently.
    @Model(name = "themeMap")
    static final Map<String, String> themeMap1 = Collections.unmodifiableMap(new LinkedHashMap<>(Map.ofEntries(
            entry("Tango", "#2e3436,#cc0000,#4e9a06,#c4a000,#3465a4,#75507b,#06989a,#d3d7cf,#555753,#ef2929,#8ae234,#fce94f,#729fcf,#ad7fa8,#34e2e2,#eeeeec"),
            entry("XTerm", "#000000,#cd0000,#00cd00,#cdcd00,#0000ee,#cd00cd,#00cdcd,#e5e5e5,#7f7f7f,#ff0000,#00ff00,#ffff00,#5c5cff,#ff00ff,#00ffff,#ffffff")
    )));
    @Model(name = "planeMap")
    static final Map<String, String> planeMap1 = Collections.unmodifiableMap(new LinkedHashMap<>(Map.ofEntries(
            entry("Black on light yellow", "#FFFFDD,#000000"),
            entry("Black on white", "#FFFFFF,#000000"),
            entry("Gray on black", "#000000,#AAAAAA"),
            entry("Green on black", "#000000,#00FF00"),
            entry("White on black", "#000000,#FFFFFF")
    )));

    // Deliberately global: this is the one application SSH key, the same for every user, and
    // a manager replacing it through importKey() must change what everyone else is shown.
    // volatile so that write is visible to the request threads reading it. It must never be
    // settable from a request parameter - the page tells users to install this key in
    // authorized_keys, so an attacker who could overwrite it could have users authorize a
    // key of the attacker's choosing. BaseKontroller's binder skips static fields for that
    // reason; this is not a per-request model value.
    @Model(name = "publicKey")
    static volatile String publicKey;

    // Shown next to the application public key because they answer the same question - what
    // Bastillion presents to a host. (Manage -> Host Keys covers the opposite direction: what
    // hosts present to us.) Global and effectively fixed, like publicKey above, and equally
    // off-limits to the request binder because it is static.
    @Model(name = "certAuthorityPublicKey")
    static volatile String certAuthorityPublicKey;

    @Model(name = "certificateAuthEnabled")
    Boolean certificateAuthEnabled = SshCertificateAuth.isEnabled();

    // Initialized rather than left null: BaseKontroller only default-constructs a model
    // object when a request parameter names it, so POSTing passwordSubmit.ktrl or
    // themeSubmit.ktrl with no auth.* / userSettings.* parameters at all left these null and
    // the resulting NPE surfaced as an HTTP 500. Validation now reports the missing fields.
    @Model(name = "auth")
    Auth auth = new Auth();
    @Model(name = "userSettings")
    UserSettings userSettings = new UserSettings();
    @Model(name = "importPrivateKey")
    String importPrivateKey;
    @Model(name = "importPublicKey")
    String importPublicKey;
    @Model(name = "importPassphrase")
    String importPassphrase;
    @Model(name = "importConfirmReplace")
    Boolean importConfirmReplace;
    @Model(name = "systemCount")
    Integer systemCount;

    static {
        try {
            publicKey = PrivateKeyDB.getApplicationKey().getPublicKey();
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
        }
        try {
            CertAuthority ca = CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA);
            certAuthorityPublicKey = ca == null ? null : ca.getPublicKey();
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
        }
    }


    public UserSettingsKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/admin/userSettings", method = MethodType.GET)
    public String userSettings() throws ServletException {

        try {
            userSettings = UserThemeDB.getTheme(AuthUtil.getUserId(getRequest().getSession()));
            systemCount = SystemDB.getSystemCount();
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return "/admin/user_settings.html";
    }

    @Kontrol(path = "/admin/passwordSubmit", method = MethodType.POST)
    public String passwordSubmit() throws ServletException {
        String retVal = "/admin/user_settings.html";

        if (!auth.getPassword().equals(auth.getPasswordConfirm())) {
            addError("Passwords do not match");

        } else if (!PasswordUtil.isValid(auth.getPassword())) {
            addError(PasswordUtil.PASSWORD_REQ_ERROR_MSG);

        } else {
            try {
                auth.setAuthToken(AuthUtil.getAuthToken(getRequest().getSession()));

                if (AuthDB.updatePassword(auth)) {
                    retVal = "redirect:/admin/menu.html";
                } else {
                    addError("Current password is invalid");
                }
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }

        }

        return retVal;
    }

    @Kontrol(path = "/admin/themeSubmit", method = MethodType.POST)
    public String themeSubmit() throws ServletException {
        // setTheme(getTheme()), setPlane(getPlane()) and setUiTheme(getUiTheme()) used to be
        // called here. Each assigned a field to itself; the values are already bound from the
        // request by the time this runs.
        try {
            UserThemeDB.saveTheme(AuthUtil.getUserId(getRequest().getSession()), userSettings);
            ThemeUtil.setThemeCookie(getRequest(), getResponse(), userSettings.getUiTheme());
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }


        return "redirect:/admin/menu.html";
    }

    /**
     * Replaces the application's SSH keypair with a pasted one, live - no restart. Manager
     * only (checked server-side, not just hidden in the UI, since /admin/* is reachable by
     * non-manager account types too). If systems are already registered, requires an
     * explicit confirmation checkbox first: this key becomes what every registered system
     * is contacted with immediately, so an unprepared replacement locks Bastillion out of
     * all of them until the new key is added to each one's authorized_keys by hand.
     */
    @Kontrol(path = "/admin/importAppKeySubmit", method = MethodType.POST)
    public String importAppKeySubmit() throws ServletException {
        String retVal = "/admin/user_settings.html";

        try {
            systemCount = SystemDB.getSystemCount();

            if (!Auth.MANAGER.equals(AuthUtil.getUserType(getRequest().getSession()))) {
                addError("Only managers can replace the application SSH key");
                return retVal;
            }

            if (systemCount > 0 && !Boolean.TRUE.equals(importConfirmReplace)) {
                addError("You have " + systemCount + " registered system(s). Check the confirmation box "
                        + "to proceed - only do this once this key is already in authorized_keys on "
                        + "every one of them, or Bastillion will immediately lose SSH access to all of them.");
                return retVal;
            }

            if (StringUtils.isBlank(importPrivateKey) || StringUtils.isBlank(importPublicKey)) {
                // Checked before validateKeyPair, which dereferences both.
                addError("Both the private key and the public key are required");
                return retVal;
            }

            SSHUtil.validateKeyPair(importPrivateKey, importPublicKey, importPassphrase);
            PrivateKeyDB.updateApplicationKey(importPublicKey.trim(), importPrivateKey, importPassphrase);
            publicKey = importPublicKey.trim();

        } catch (JSchException ex) {
            addError(ex.getMessage());
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return retVal;
    }

    /**
     * Serves the certificate authority public key as a file.
     * <p>
     * The install step is literally "put this file on every host", so handing over
     * {@code bastillion_ca.pub} directly avoids a copy-paste that can arrive truncated or with
     * a stray newline - which then fails on the far end with nothing useful in the logs.
     * Writes the response itself and returns null, as the other download actions here do.
     */
    @Kontrol(path = "/admin/downloadCertAuthority", method = MethodType.GET)
    public String downloadCertAuthority() throws ServletException {
        try {
            if (!Auth.MANAGER.equals(AuthUtil.getUserType(getRequest().getSession()))) {
                getResponse().sendError(HttpServletResponse.SC_FORBIDDEN);
                return null;
            }
            if (StringUtils.isBlank(certAuthorityPublicKey)) {
                getResponse().sendError(HttpServletResponse.SC_NOT_FOUND);
                return null;
            }
            getResponse().setContentType("application/octet-stream");
            getResponse().setHeader("Content-Disposition", "attachment;filename=bastillion_ca.pub");
            try (OutputStream out = getResponse().getOutputStream()) {
                out.write((certAuthorityPublicKey.trim() + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (IOException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException("Request processing failed");
        }
        return null;
    }

    /**
     * Validates fields for password submit
     */
    @Validate(input = "/admin/user_settings.html")
    public void validatePasswordSubmit() {
        if (auth.getPassword() == null ||
                auth.getPassword().trim().equals("")) {
            addFieldError("auth.password", REQUIRED);
        }
        if (auth.getPasswordConfirm() == null ||
                auth.getPasswordConfirm().trim().equals("")) {
            addFieldError("auth.passwordConfirm", REQUIRED);
        }
        if (auth.getPrevPassword() == null ||
                auth.getPrevPassword().trim().equals("")) {
            addFieldError("auth.prevPassword", REQUIRED);
        }
    }
}
