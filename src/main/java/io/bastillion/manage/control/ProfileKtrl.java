/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.manage.db.ProfileDB;
import io.bastillion.manage.model.Profile;
import io.bastillion.manage.model.SortedSet;
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
 * Action to manage profiles
 */
public class ProfileKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(ProfileKtrl.class);

    @Model(name = "sortedSet")
    SortedSet sortedSet = new SortedSet();
    @Model(name = "profile")
    Profile profile = new Profile();

    public ProfileKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }


    @Kontrol(path = "/manage/viewProfiles", method = MethodType.GET)
    public String viewSystems() throws ServletException {

        try {
            sortedSet = ProfileDB.getProfileSet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return "/manage/view_profiles.html";
    }

    @Kontrol(path = "/manage/saveProfile", method = MethodType.POST)
    public String saveProfile() throws ServletException {

        try {
            if (profile.getId() != null) {
                ProfileDB.updateProfile(profile);
            } else {
                ProfileDB.insertProfile(profile);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/manage/viewProfiles.ktrl?" + sortedSet.toQueryString();
    }


    @Kontrol(path = "/manage/deleteProfile", method = MethodType.GET)
    public String deleteProfile() throws ServletException {

        if (profile.getId() != null) {
            try {
                ProfileDB.deleteProfile(profile.getId());
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }
        return "redirect:/manage/viewProfiles.ktrl?" + sortedSet.toQueryString();
    }

    /**
     * validate save profile
     */
    @Validate(input = "/manage/view_profiles.html")
    public void validateSaveProfile() throws ServletException {
        if (profile == null
                || profile.getNm() == null
                || profile.getNm().trim().equals("")) {
            addFieldError("profile.nm", "Required");
        }

        if (!this.getFieldErrors().isEmpty()) {
            try {
                sortedSet = ProfileDB.getProfileSet(sortedSet);
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }
    }
}
