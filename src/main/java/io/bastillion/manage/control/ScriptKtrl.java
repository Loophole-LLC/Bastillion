/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.ScriptDB;
import io.bastillion.manage.model.Script;
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
 * Action to manage scripts
 */
public class ScriptKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(ScriptKtrl.class);

    @Model(name = "sortedSet")
    SortedSet sortedSet = new SortedSet();
    @Model(name = "script")
    Script script = new Script();

    public ScriptKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/admin/viewScripts", method = MethodType.GET)
    public String viewScripts() throws ServletException {
        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            sortedSet = ScriptDB.getScriptSet(sortedSet, userId);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        return "/admin/view_scripts.html";
    }


    @Kontrol(path = "/admin/saveScript", method = MethodType.POST)
    public String saveScript() throws ServletException {
        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            if (script.getId() != null) {
                ScriptDB.updateScript(script, userId);
            } else {
                ScriptDB.insertScript(script, userId);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/admin/viewScripts.ktrl?" + sortedSet.toQueryString();
    }

    @Kontrol(path = "/admin/deleteScript", method = MethodType.GET)
    public String deleteScript() throws ServletException {

        if (script.getId() != null) {
            try {
                Long userId = AuthUtil.getUserId(getRequest().getSession());
                ScriptDB.deleteScript(script.getId(), userId);
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }
        return "redirect:/admin/viewScripts.ktrl?" + sortedSet.toQueryString();
    }


    /**
     * Validates all fields for adding a user
     */
    @Validate(input = "/admin/view_scripts.html")
    public void validateSaveScript() throws ServletException {
        if (script == null
                || script.getDisplayNm() == null
                || script.getDisplayNm().trim().equals("")) {
            addFieldError("script.displayNm", "Required");
        }

        if (script == null
                || script.getScript() == null
                || script.getScript().trim().equals("")
                || (new Script()).getScript().trim().equals(script.getScript().trim())) {
            addFieldError("script.script", "Required");
        }

        if (!this.getFieldErrors().isEmpty()) {
            try {
                Long userId = AuthUtil.getUserId(getRequest().getSession());
                sortedSet = ScriptDB.getScriptSet(sortedSet, userId);
            } catch (SQLException | GeneralSecurityException ex) {
                log.error(ex.toString(), ex);
                throw new ServletException(ex.toString(), ex);
            }
        }
    }
}
