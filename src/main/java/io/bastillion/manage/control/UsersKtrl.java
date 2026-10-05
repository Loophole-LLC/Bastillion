/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.PublicKeyDB;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.model.User;
import io.bastillion.manage.util.PasswordUtil;
import io.bastillion.manage.util.RefreshAuthKeyUtil;
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

/**
 * Action to manage users
 */
public class UsersKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(UsersKtrl.class);
    public static final String REQUIRED = "Required";

    @Model(name = "sortedSet")
    SortedSet sortedSet = new SortedSet();
    @Model(name = "user")
    User user = new User();
    @Model(name = "resetSharedSecret")
    Boolean resetSharedSecret = false;
    @Model(name = "userId")
    Long userId;


    public UsersKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/manage/viewUsers", method = MethodType.GET)
    public String viewUsers() throws ServletException {
        try {
            userId = AuthUtil.getUserId(getRequest().getSession());
            sortedSet = UserDB.getUserSet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return "/manage/view_users.html";
    }

    @Kontrol(path = "/manage/saveUser", method = MethodType.POST)
    public String saveUser() throws ServletException {
        String retVal = "redirect:/manage/viewUsers.ktrl?" + sortedSet.toQueryString();

        try {
            if (user.getId() != null) {
                if (user.getPassword() == null || user.getPassword().trim().equals("")) {
                    UserDB.updateUserNoCredentials(user);
                } else {
                    UserDB.updateUserCredentials(user);
                }
                //check if reset is set
                if (resetSharedSecret) {
                    UserDB.resetSharedSecret(user.getId());
                }
            } else {
                UserDB.insertUser(user);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return retVal;
    }

    @Kontrol(path = "/manage/deleteUser", method = MethodType.GET)
    public String deleteUser() throws ServletException {

        try {
            if (user.getId() != null && !user.getId().equals(AuthUtil.getUserId(getRequest().getSession()))) {
                UserDB.deleteUser(user.getId());
                PublicKeyDB.deleteUserPublicKeys(user.getId());
                RefreshAuthKeyUtil.refreshAllSystems();
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/manage/viewUsers.ktrl?" + sortedSet.toQueryString();
    }

    @Kontrol(path = "/manage/unlockUser", method = MethodType.GET)
    public String unlockUser() throws ServletException {

        try {
            if (user.getId() != null && !user.getId().equals(AuthUtil.getUserId(getRequest().getSession()))) {
                UserDB.unlockAccount(user.getId());
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/manage/viewUsers.ktrl?" + sortedSet.toQueryString();
    }

    /**
     * Validates all fields for adding a user
     */
    @Validate(input = "/manage/view_users.html")
    public void validateSaveUser() throws ServletException {
        if (user == null
                || user.getUsername() == null
                || user.getUsername().trim().equals("")) {
            addFieldError("user.username", REQUIRED);
        }

        if (user == null
                || user.getLastNm() == null
                || user.getLastNm().trim().equals("")) {
            addFieldError("user.lastNm", REQUIRED);
        }

        if (user == null
                || user.getFirstNm() == null
                || user.getFirstNm().trim().equals("")) {
            addFieldError("user.firstNm", REQUIRED);
        }

        if (user != null && user.getPassword() != null && !user.getPassword().trim().equals("")) {

            if (!user.getPassword().equals(user.getPasswordConfirm())) {
                addError("Passwords do not match");
            } else if (!PasswordUtil.isValid(user.getPassword())) {
                addError(PasswordUtil.PASSWORD_REQ_ERROR_MSG);
            }
        }
        if (user != null && user.getId() == null && !Auth.AUTH_EXTERNAL.equals(user.getAuthType()) && (user.getPassword() == null || user.getPassword().trim().equals(""))) {
            addError("Password is required");
        }

        try {
            if (user != null && !UserDB.isUnique(user.getId(), user.getUsername())) {
                addError("Username has been taken");
            }
            if (!this.getFieldErrors().isEmpty() || !this.getErrors().isEmpty()) {
                userId = AuthUtil.getUserId(getRequest().getSession());
                sortedSet = UserDB.getUserSet(sortedSet);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
    }
}
