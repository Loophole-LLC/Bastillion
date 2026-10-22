/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.manage.db.ProfileDB;
import io.bastillion.manage.db.ProfileSystemsDB;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.model.Profile;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.util.RefreshAuthKeyUtil;
import loophole.mvc.annotation.Kontrol;
import loophole.mvc.annotation.MethodType;
import loophole.mvc.annotation.Model;
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
 * Action to assign systems to profiles
 */
public class ProfileSystemsKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(ProfileSystemsKtrl.class);

    @Model(name = "profile", params = {"profile.id"})
    Profile profile;
    @Model(name = "sortedSet", params = {"sortedSet.orderByField", "sortedSet.orderByDirection"})
    SortedSet sortedSet = new SortedSet();
    @Model(name = "systemSelectId", params = {"systemSelectId"})
    List<Long> systemSelectId = new ArrayList<>();


    public ProfileSystemsKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }


    @Kontrol(path = "/manage/viewProfileSystems", method = MethodType.GET)
    public String viewProfileSystems() throws ServletException {
        if (profile != null && profile.getId() != null) {
            try {
                profile = ProfileDB.getProfile(profile.getId());
                sortedSet = SystemDB.getSystemSet(sortedSet, profile.getId());
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }

        return "/manage/view_profile_systems.html";
    }


    @Kontrol(path = "/manage/assignSystemsToProfile", method = MethodType.POST)
    public String assignSystemsToProfile() throws ServletException {

        if (systemSelectId != null) {
            try {
                ProfileSystemsDB.setSystemsForProfile(profile.getId(), systemSelectId);
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }

        RefreshAuthKeyUtil.refreshProfileSystems(profile.getId());
        return "redirect:/manage/viewProfiles.ktrl";
    }


}
