/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.common.util.AppConfig;
import io.bastillion.common.util.AuditLogUtil;
import io.bastillion.manage.db.AuthDB;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.db.UserProfileDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.User;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

/**
 * Turns an identity an external source has already authenticated - an LDAP bind or a signed
 * SAML assertion - into a session on a local account. This is the one place that decides
 * which account an external login becomes: SAML and LDAP each used to do it themselves, and
 * the lookup they shared matched usernames as a LIKE pattern (GHSA-5qgc-52c7-26mg).
 */
public class ExternalAccountUtil {

    private static final Logger log = LoggerFactory.getLogger(ExternalAccountUtil.class);

    /**
     * Whether an external login may take over an existing Basic (local-password) account
     * with the same username. Linking clears that account's local password, so an IdP or
     * directory identity named "admin" becomes the bootstrap admin account. Defaults to true,
     * which is how every release before this behaved.
     */
    static final boolean LINK_BASIC_ACCOUNTS = !"false".equals(AppConfig.getProperty("externalAuthLinkBasicAccounts", "true"));

    private ExternalAccountUtil() {
    }

    /**
     * Finds or creates the local account for an externally authenticated user, syncs its
     * profiles, and issues it a new auth token.
     *
     * @param con             DB connection
     * @param newUser         username, plus the name and email to use if the account has to be created
     * @param authType        {@link Auth#AUTH_EXTERNAL} or {@link Auth#AUTH_SAML}
     * @param allProfileNames every profile name the source can speak for, or null to leave
     *                        membership alone
     * @param assignedRoles   the roles this login asserted
     * @param defaultProfile  profile every user from this source is added to, or blank for none
     * @return auth token, or null if the login matched an account it may not link to
     */
    public static String link(Connection con, User newUser, String authType, List<String> allProfileNames,
                              List<String> assignedRoles, String defaultProfile) throws SQLException, GeneralSecurityException {
        return link(con, newUser, authType, allProfileNames, assignedRoles, defaultProfile, LINK_BASIC_ACCOUNTS);
    }

    static String link(Connection con, User newUser, String authType, List<String> allProfileNames,
                       List<String> assignedRoles, String defaultProfile, boolean linkBasicAccounts)
            throws SQLException, GeneralSecurityException {

        User user = AuthDB.getUserByUID(con, newUser.getUsername());
        if (user == null) {
            newUser.setUserType(User.ADMINISTRATOR);
            newUser.setAuthType(authType);
            newUser.setId(UserDB.insertUser(con, newUser));
            user = newUser;
        } else if (Auth.AUTH_BASIC.equals(user.getAuthType()) && !linkBasicAccounts) {
            log.warn("Refused " + authType + " login for " + AuditLogUtil.safe(user.getUsername())
                    + ": it matches a Basic account and externalAuthLinkBasicAccounts=false");
            return null;
        }

        if (allProfileNames != null) {
            UserProfileDB.assignProfilesToUser(con, user.getId(), allProfileNames, assignedRoles);
        }
        if (StringUtils.isNotEmpty(defaultProfile)) {
            UserProfileDB.assignProfileToUser(con, user.getId(), defaultProfile);
        }

        String authToken = UUID.randomUUID().toString();
        user.setAuthToken(authToken);
        user.setAuthType(authType);
        AuthDB.updateLogin(con, user);
        return authToken;
    }
}
