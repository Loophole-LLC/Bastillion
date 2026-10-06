/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.ProfileDB;
import io.bastillion.manage.db.ScriptDB;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.db.UserProfileDB;
import io.bastillion.manage.model.*;
import io.bastillion.manage.util.LicenseUtil;
import io.bastillion.manage.util.SSHUtil;
import io.bastillion.manage.util.SshCertificateAuth;
import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
import loophole.mvc.annotation.Validate;
import loophole.mvc.base.BaseKontroller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Action to manage systems
 */
public class SystemKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(SystemKtrl.class);

    public static final String REQUIRED = "Required";
    @Model(name = "sortedSet")
    SortedSet sortedSet = new SortedSet();
    @Model(name = "hostSystem")
    HostSystem hostSystem = new HostSystem();
    @Model(name = "script")
    Script script = null;
    @Model(name = "password")
    String password;
    @Model(name = "passphrase")
    String passphrase;
    @Model(name = "profileList")
    List<Profile> profileList = new ArrayList<>();
    @Model(name = "certTestMessage")
    String certTestMessage;
    @Model(name = "certTestOk")
    Boolean certTestOk;
    // static so the request binder leaves it alone - it skips static fields.
    @Model(name = "certificateAuthEnabled")
    static final Boolean certificateAuthEnabled = SshCertificateAuth.isEnabled();

    public SystemKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/admin/viewSystems", method = MethodType.GET)
    public String viewAdminSystems() throws ServletException {

        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            if (Auth.MANAGER.equals(AuthUtil.getUserType(getRequest().getSession()))) {
                sortedSet = SystemDB.getSystemSet(sortedSet);
                profileList = ProfileDB.getAllProfiles();
            } else {
                sortedSet = SystemDB.getUserSystemSet(sortedSet, userId);
                profileList = UserProfileDB.getProfilesByUser(userId);
            }
            if (script != null && script.getId() != null) {
                script = ScriptDB.getScript(script.getId(), userId);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return "/admin/view_systems.html";
    }

    @Kontrol(path = "/manage/viewSystems", method = MethodType.GET)
    public String viewManageSystems() throws ServletException {
        // Cleared because these are bound from request parameters like any other model field,
        // and they cannot be static the way the flags above are - they carry a per-request
        // result. Without this, a link with ?certTestOk=true&certTestMessage=... renders
        // "Certificate accepted" and arbitrary text for a host nobody tested. Only
        // testCertificateAuth sets them now.
        certTestOk = null;
        certTestMessage = null;
        try {
            sortedSet = SystemDB.getSystemSet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "/manage/view_systems.html";
    }

    @Kontrol(path = "/manage/saveSystem", method = MethodType.POST)
    public String saveSystem() throws ServletException {
        String retVal = "redirect:/manage/viewSystems.ktrl?" + sortedSet.toQueryString();

        boolean isNewSystem = hostSystem.getId() == null;

        try {
            if (isNewSystem && SystemDB.getSystemCount() >= LicenseUtil.getMaxSystems()) {
                addError("License limit reached: this Bastillion instance is licensed for " +
                        LicenseUtil.getMaxSystems() + " system" + (LicenseUtil.getMaxSystems() == 1 ? "" : "s") +
                        ". Remove a system or upgrade your license to add another.");
                sortedSet = SystemDB.getSystemSet(sortedSet);
                return "/manage/view_systems.html";
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        hostSystem = SSHUtil.authAndAddPubKey(hostSystem, passphrase, password);

        try {
            if (!isNewSystem) {
                SystemDB.updateSystem(hostSystem);
            } else {
                hostSystem.setId(SystemDB.insertSystem(hostSystem));
            }
            sortedSet = SystemDB.getSystemSet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }


        if (!HostSystem.SUCCESS_STATUS.equals(hostSystem.getStatusCd())) {
            retVal = "/manage/view_systems.html";
        }
        return retVal;
    }

    /**
     * Tries a certificate-authenticated connection to one system and reports the result.
     * <p>
     * {@code sshCertificateAuth} is a single global switch, so without this the way to find out
     * that a host was never given TrustedUserCAKeys is to turn certificates on for the whole
     * fleet and watch it fail. POST rather than a link: it opens a real SSH connection.
     */
    @Kontrol(path = "/manage/testCertificateAuth", method = MethodType.POST)
    public String testCertificateAuth() throws ServletException {
        try {
            if (hostSystem.getId() == null) {
                addError("No system selected");
                return reloadSystems();
            }
            HostSystem target = SystemDB.getSystem(hostSystem.getId());
            if (target == null) {
                addError("That system no longer exists");
                return reloadSystems();
            }
            SSHUtil.CertificateTestResult result = SSHUtil.testCertificateAuth(
                    target, AuthUtil.getUsername(getRequest().getSession()));
            certTestOk = result.ok();
            certTestMessage = result.message();
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return reloadSystems();
    }

    private String reloadSystems() throws ServletException {
        try {
            sortedSet = SystemDB.getSystemSet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "/manage/view_systems.html";
    }

    @Kontrol(path = "/manage/deleteSystem", method = MethodType.GET)
    public String deleteSystem() throws ServletException {

        if (hostSystem.getId() != null) {
            try {
                SystemDB.deleteSystem(hostSystem.getId());
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }

        }
        return "redirect:/manage/viewSystems.ktrl?" + sortedSet.toQueryString();
    }

    /**
     * Validates all fields for adding a host system
     */
    @Validate(input = "/manage/view_systems.html")
    public void validateSaveSystem() throws ServletException {
        if (hostSystem == null
                || hostSystem.getDisplayNm() == null
                || hostSystem.getDisplayNm().trim().equals("")) {
            addFieldError("hostSystem.displayNm", REQUIRED);
        }
        if (hostSystem == null
                || hostSystem.getUser() == null
                || hostSystem.getUser().trim().equals("")) {
            addFieldError("hostSystem.user", REQUIRED);
        }
        if (hostSystem == null
                || hostSystem.getHost() == null
                || hostSystem.getHost().trim().equals("")) {
            addFieldError("hostSystem.host", REQUIRED);
        }
        if (hostSystem == null
                || hostSystem.getPort() == null) {
            addFieldError("hostSystem.port", REQUIRED);
        } else if (!(hostSystem.getPort() > 0)) {
            addFieldError("hostSystem.port", "Invalid");
        }

        if (hostSystem == null
                || hostSystem.getAuthorizedKeys() == null
                || hostSystem.getAuthorizedKeys().trim().equals("") || hostSystem.getAuthorizedKeys().trim().equals("~")) {
            addFieldError("hostSystem.authorizedKeys", REQUIRED);
        }

        if (!this.getFieldErrors().isEmpty()) {

            try {
                sortedSet = SystemDB.getSystemSet(sortedSet);
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }

        }

    }

}
