/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import io.bastillion.common.saml.SamlSettingsUtil;
import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.db.ProfileDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.Profile;
import io.bastillion.manage.model.User;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import jakarta.servlet.http.HttpServletRequest;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * External authentication utility for SAML 2.0 SSO (e.g. Microsoft Entra ID). Mirrors
 * ExternalAuthUtil's shape for JAAS/LDAP: validate the incoming credential (there, a
 * username/password against a JAAS LoginModule; here, an IdP-signed assertion), then hand the
 * NameID and the IdP's role/group claim to ExternalAccountUtil, which links it to a local
 * account, syncs profiles and issues the auth token.
 */
public class SamlAuthUtil {

    private static final Logger log = LoggerFactory.getLogger(SamlAuthUtil.class);

    public static final boolean samlAuthEnabled = StringUtils.isNotEmpty(AppConfig.getProperty("samlIdpMetadataUrl"))
            || StringUtils.isNotEmpty(AppConfig.getProperty("samlIdpSsoUrl"));

    //Entra ID's default group-claim URI; override via SAML_ROLE_ATTRIBUTE for a different
    //IdP or for an app-roles-based setup (Entra's "roles" claim, etc.)
    private static final String ROLE_ATTRIBUTE = AppConfig.getProperty("samlRoleAttribute",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups");
    private static final String DEFAULT_SAML_PROFILE = AppConfig.getProperty("defaultProfileForSaml");

    private SamlAuthUtil() {
    }

    /**
     * Validates the SAML Response POSTed to the ACS endpoint and, on success, provisions or
     * updates the matching User row.
     *
     * @return auth token if the assertion is valid, null if it is not or SAML is off
     * @throws ExternalAuthException if SAML is misconfigured or the IdP settings cannot be loaded
     */
    public static String login(HttpServletRequest servletRequest)
            throws ExternalAuthException, SQLException, GeneralSecurityException {
        if (!samlAuthEnabled) {
            return null;
        }

        Saml2Settings settings;
        try {
            settings = SamlSettingsUtil.getSettings();
        } catch (Exception ex) {
            throw new ExternalAuthException("SAML settings could not be loaded", ex);
        }

        //no requestId argument - isValid() (not isValid(requestId)) deliberately, so
        //both SP-initiated and IdP-initiated (e.g. clicked from the IdP's app portal)
        //logins validate cleanly; there is no Bastillion-issued request to correlate
        //against for the latter, and no pre-redirect session state survives the
        //cross-origin POST anyway (see SamlAcsServlet).
        SamlResponse samlResponse;
        try {
            samlResponse = new SamlResponse(settings, new HttpRequest(servletRequest.getRequestURL().toString(),
                    toParameterMap(servletRequest)));
        } catch (SettingsException | ParserConfigurationException ex) {
            throw new ExternalAuthException("SAML is misconfigured", ex);
        } catch (XPathExpressionException | SAXException | IOException | ValidationError ex) {
            //what was POSTed is not a SAML response we can read - a bad request, not an outage
            log.debug("SAML response unreadable: " + ex);
            return null;
        }
        if (!samlResponse.isValid()) {
            log.debug("SAML response invalid: " + samlResponse.getError());
            return null;
        }

        String username;
        List<String> assignedRoles;
        try {
            username = samlResponse.getNameId();
            assignedRoles = samlResponse.getAttributes().getOrDefault(ROLE_ATTRIBUTE, new ArrayList<>());
        } catch (Exception ex) {
            log.debug("SAML response unreadable: " + ex);
            return null;
        }
        if (StringUtils.isEmpty(username)) {
            return null;
        }

        try (Connection con = DBUtils.getConn()) {
            //a SAML assertion only ever tells us this user's roles, so unlike LDAP (which can
            //enumerate every role the directory knows about via getAllRoles()) the names to
            //recompute membership for are every Bastillion-side profile name instead
            List<String> allProfileNames = new ArrayList<>();
            for (Profile profile : ProfileDB.getAllProfiles(con)) {
                allProfileNames.add(profile.getNm());
            }

            User newUser = new User();
            newUser.setUsername(username);
            return ExternalAccountUtil.link(con, newUser, Auth.AUTH_SAML, allProfileNames, assignedRoles, DEFAULT_SAML_PROFILE);
        }
    }

    private static Map<String, List<String>> toParameterMap(HttpServletRequest request) {
        Map<String, List<String>> parameters = new HashMap<>();
        for (Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            parameters.put(entry.getKey(), Arrays.asList(entry.getValue()));
        }
        return parameters;
    }
}
