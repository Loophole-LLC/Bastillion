/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuditLogUtil;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.HostKeyDB;
import io.bastillion.manage.model.KnownHostKey;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.util.HostKeyVerifier;
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

/**
 * Review and approve the SSH host keys Bastillion has seen managed systems present.
 * <p>
 * Mapped under /manage/, so AuthFilter admits managers only - approving a host key decides
 * what Bastillion will hand the application private key to, which is not a per-user setting.
 */
public class HostKeyKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(HostKeyKtrl.class);
    private static final Logger hostKeyAuditLogger =
            LoggerFactory.getLogger("io.bastillion.manage.control.LoginAudit");

    @Model(name = "sortedSet")
    SortedSet sortedSet = new SortedSet();
    @Model(name = "hostKey")
    KnownHostKey hostKey = new KnownHostKey();
    @Model(name = "hostKeyVerificationEnabled")
    Boolean hostKeyVerificationEnabled = HostKeyVerifier.isEnabled();

    public HostKeyKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Kontrol(path = "/manage/viewHostKeys", method = MethodType.GET)
    public String viewHostKeys() throws ServletException {
        if (sortedSet.getOrderByField() == null || sortedSet.getOrderByField().trim().isEmpty()) {
            sortedSet.setOrderByField(HostKeyDB.SORT_BY_HOST);
            sortedSet.setOrderByDirection("asc");
        }
        try {
            sortedSet = HostKeyDB.getHostKeySet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "/manage/view_host_keys.html";
    }

    /**
     * Trusts a host key: approves a newly seen one, or accepts a changed host's new key.
     * <p>
     * POST rather than a GET link like the delete actions on the other manage screens. This
     * is the control that decides whether a host key change is treated as legitimate, so it
     * should not be reachable by anything that merely dereferences a URL.
     */
    @Kontrol(path = "/manage/approveHostKey", method = MethodType.POST)
    public String approveHostKey() throws ServletException {
        try {
            if (hostKey.getId() != null) {
                KnownHostKey existing = reload(hostKey.getId());
                HostKeyDB.approveHostKey(hostKey.getId(), AuthUtil.getUserId(getRequest().getSession()));
                audit("approved", existing);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/manage/viewHostKeys.ktrl?" + sortedSet.toQueryString();
    }

    @Kontrol(path = "/manage/revokeHostKey", method = MethodType.POST)
    public String revokeHostKey() throws ServletException {
        try {
            if (hostKey.getId() != null) {
                KnownHostKey existing = reload(hostKey.getId());
                HostKeyDB.revokeHostKey(hostKey.getId());
                audit("revoked", existing);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/manage/viewHostKeys.ktrl?" + sortedSet.toQueryString();
    }

    /**
     * Forgets a host key, so the next connection treats the host as newly seen. For a system
     * that really was rebuilt and whose row is no longer wanted at all.
     */
    @Kontrol(path = "/manage/deleteHostKey", method = MethodType.POST)
    public String deleteHostKey() throws ServletException {
        try {
            if (hostKey.getId() != null) {
                KnownHostKey existing = reload(hostKey.getId());
                HostKeyDB.deleteHostKey(hostKey.getId());
                audit("deleted", existing);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }
        return "redirect:/manage/viewHostKeys.ktrl?" + sortedSet.toQueryString();
    }

    /**
     * Reads the row back before changing it, so the audit line records which host and
     * fingerprint the decision was actually about rather than just a row id.
     */
    private KnownHostKey reload(Long id) throws SQLException, GeneralSecurityException {
        return HostKeyDB.getHostKey(id);
    }

    private void audit(String action, KnownHostKey subject) {
        String username = AuthUtil.getUsername(getRequest().getSession());
        if (subject == null) {
            hostKeyAuditLogger.info("{} - host key {} (id {})",
                    AuditLogUtil.safe(username), action, hostKey.getId());
            return;
        }
        hostKeyAuditLogger.info("{} - host key {} for {}:{} {} {}",
                AuditLogUtil.safe(username), action,
                AuditLogUtil.safe(subject.getHost()), subject.getPort(),
                AuditLogUtil.safe(subject.getType()),
                AuditLogUtil.safe(subject.getOfferedFingerprint() != null
                        ? subject.getOfferedFingerprint() : subject.getFingerprint()));
    }
}
