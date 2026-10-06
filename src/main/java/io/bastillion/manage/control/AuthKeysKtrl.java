/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */

package io.bastillion.manage.control;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import io.bastillion.common.util.AppConfig;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.*;
import io.bastillion.manage.model.*;
import io.bastillion.manage.util.EncryptionUtil;
import io.bastillion.manage.util.PasswordUtil;
import io.bastillion.manage.util.RefreshAuthKeyUtil;
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
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Controller to manage SSH key generation, validation, and distribution.
 */
public class AuthKeysKtrl extends BaseKontroller {

    private static final Logger log = LoggerFactory.getLogger(AuthKeysKtrl.class);

    private static final String REQUIRED = "Required";
    private static final String INVALID = "Invalid";
    private static final String PUBLIC_KEY_PUBLIC_KEY = "publicKey.publicKey";
    private static final String PVT_KEY = "privateKey";

    @Model(name = "profileList")
    List<Profile> profileList = new ArrayList<>();

    @Model(name = "userList")
    List<User> userList = new ArrayList<>();

    @Model(name = "publicKey")
    PublicKey publicKey;

    @Model(name = "sortedSet")
    SortedSet sortedSet = new SortedSet();

    @Model(name = "forceUserKeyGenEnabled")
    boolean forceUserKeyGenEnabled = "true".equals(AppConfig.getProperty("forceUserKeyGeneration"));

    @Model(name = "allowUserKeyTypeSelection")
    boolean allowUserKeyTypeSelection = SSHUtil.ALLOW_USER_KEY_TYPE_SELECTION;

    @Model(name = "hostSystem")
    HostSystem hostSystem = new HostSystem();

    @Model(name = "userPublicKeyList")
    List<PublicKey> userPublicKeyList = new ArrayList<>();

    @Model(name = "existingKeyId")
    Long existingKeyId;

    /**
     * Whether to offer a downloadable certificate per key - meaningless unless the hosts have
     * been told to trust the authority, which is what sshCertificateAuth being on implies.
     */
    @Model(name = "certificateAuthEnabled")
    Boolean certificateAuthEnabled = SshCertificateAuth.isEnabled();

    public AuthKeysKtrl(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    /* ------------------------- Public Key Enable/Disable ------------------------- */

    @Kontrol(path = "/manage/enablePublicKey", method = MethodType.GET)
    public String enablePublicKey() throws ServletException {
        try {
            publicKey = PublicKeyDB.getPublicKey(publicKey.getId());
            PublicKeyDB.enableKey(publicKey.getId());
            reloadKeyViewData();
            distributePublicKeys(publicKey);
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }
        return "/manage/view_keys.html";
    }

    @Kontrol(path = "/manage/disablePublicKey", method = MethodType.GET)
    public String disablePublicKey() throws ServletException {
        try {
            publicKey = PublicKeyDB.getPublicKey(publicKey.getId());
            PublicKeyDB.disableKey(publicKey.getId());
            reloadKeyViewData();
            distributePublicKeys(publicKey);
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }
        return "/manage/view_keys.html";
    }

    /* ------------------------- Key View Pages ------------------------- */

    @Kontrol(path = "/manage/viewKeys", method = MethodType.GET)
    public String manageViewKeys() throws ServletException {
        try {
            profileList = ProfileDB.getAllProfiles();
            userList = UserDB.getUserSet(new SortedSet(SessionAuditDB.SORT_BY_USERNAME)).getItemList();
            sortedSet = PublicKeyDB.getPublicKeySet(sortedSet);
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }
        return "/manage/view_keys.html";
    }

    @Kontrol(path = "/admin/viewKeys", method = MethodType.GET)
    public String adminViewKeys() throws ServletException {
        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            String userType = AuthUtil.getUserType(getRequest().getSession());

            if (Auth.MANAGER.equals(userType)) {
                profileList = ProfileDB.getAllProfiles();
            } else {
                profileList = UserProfileDB.getProfilesByUser(userId);
            }

            sortedSet = PublicKeyDB.getPublicKeySet(sortedSet, userId);
            userPublicKeyList = PublicKeyDB.getUniquePublicKeysForUser(userId);
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }
        return "/admin/view_keys.html";
    }

    /* ------------------------- Key Save/Delete/Download ------------------------- */

    @Kontrol(path = "/admin/savePublicKey", method = MethodType.POST)
    public String savePublicKeys() throws ServletException {
        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            String userType = AuthUtil.getUserType(getRequest().getSession());

            publicKey.setUserId(userId);
            if (Auth.MANAGER.equals(userType) || UserProfileDB.checkIsUsersProfile(userId, publicKey.getProfile().getId())) {
                if (publicKey.getId() != null) {
                    PublicKeyDB.updatePublicKey(publicKey);
                } else {
                    PublicKeyDB.insertPublicKey(publicKey);
                }
                distributePublicKeys(publicKey);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }

        return "redirect:/admin/viewKeys.ktrl?" + sortedSet.toQueryString() + "&keyNm=" + publicKey.getKeyNm();
    }

    @Kontrol(path = "/admin/deletePublicKey", method = MethodType.GET)
    public String deletePublicKey() throws ServletException {
        try {
            if (publicKey.getId() != null) {
                publicKey = PublicKeyDB.getPublicKey(publicKey.getId());
                PublicKeyDB.deletePublicKey(publicKey.getId(), AuthUtil.getUserId(getRequest().getSession()));
            }
            distributePublicKeys(publicKey);
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }
        return "redirect:/admin/viewKeys.ktrl?" + sortedSet.toQueryString();
    }

    @Kontrol(path = "/admin/downloadPvtKey", method = MethodType.GET)
    public String downloadPvtKey() throws ServletException {
        try {
            String privateKey = EncryptionUtil.decrypt((String) getRequest().getSession().getAttribute(PVT_KEY));

            if (StringUtils.isNotEmpty(publicKey.getKeyNm()) && StringUtils.isNotEmpty(privateKey)) {
                getResponse().setContentType("application/octet-stream");
                getResponse().setHeader("Content-Disposition", "attachment;filename=" + publicKey.getKeyNm() + ".key");
                try (OutputStream out = getResponse().getOutputStream()) {
                    out.write(privateKey.getBytes());
                    out.flush();
                }
            }

            getRequest().getSession().removeAttribute(PVT_KEY);
        } catch (IOException | GeneralSecurityException ex) {
            handleException(ex);
        }

        return null;
    }

    /**
     * Signs a certificate for one of the user's own public keys and hands it back as a file,
     * so they can reach a host directly without that key being in its authorized_keys.
     * <p>
     * The key is re-read and its owner checked here. PublicKeyDB.getPublicKey(id) fetches any
     * key by id without regard to who owns it, so taking the id from the request and signing
     * whatever came back would let any signed-in user obtain a certificate for somebody else's
     * key - which is the whole credential.
     */
    @Kontrol(path = "/admin/downloadUserCertificate", method = MethodType.GET)
    public String downloadUserCertificate() throws ServletException {
        try {
            Long userId = AuthUtil.getUserId(getRequest().getSession());
            if (publicKey == null || publicKey.getId() == null) {
                getResponse().sendError(HttpServletResponse.SC_BAD_REQUEST);
                return null;
            }
            // Scoped to this user in the query - see PublicKeyDB.getPublicKeyForUser for why
            // fetching by id and comparing getUserId() afterwards does not work.
            PublicKey stored = PublicKeyDB.getPublicKeyForUser(publicKey.getId(), userId);
            if (stored == null) {
                getResponse().sendError(HttpServletResponse.SC_FORBIDDEN);
                return null;
            }

            String certificate = SshCertificateAuth.userCertificateFor(
                    stored.getPublicKey(), userId, AuthUtil.getUsername(getRequest().getSession()));

            getResponse().setContentType("application/octet-stream");
            getResponse().setHeader("Content-Disposition",
                    "attachment;filename=" + certificateFileName(stored.getKeyNm()));
            try (OutputStream out = getResponse().getOutputStream()) {
                out.write((certificate.trim() + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (GeneralSecurityException ex) {
            // Reasons a user can act on - no authority yet, no systems assigned, a key type
            // certificates cannot be issued for.
            log.error(ex.toString(), ex);
            addError(ex.getMessage());
            return adminViewKeys();
        } catch (IOException | SQLException ex) {
            handleException(ex);
        }
        return null;
    }

    /**
     * OpenSSH loads a certificate from "&lt;identity file&gt;-cert.pub", so the name has to be
     * built from whatever the private key was downloaded as - which downloadPvtKey names
     * "&lt;key name&gt;.key". Naming this "&lt;key name&gt;-cert.pub" instead would leave the
     * two files sitting next to each other with ssh quietly ignoring the certificate.
     */
    private static String certificateFileName(String keyName) {
        String base = StringUtils.isBlank(keyName) ? "id_ed25519" : keyName.replaceAll("[^A-Za-z0-9_.-]", "_");
        return base + ".key-cert.pub";
    }

    /* ------------------------- Validation ------------------------- */

    @Validate(input = "/admin/view_keys.html")
    public void validateSavePublicKeys() throws ServletException {
        Long userId;
        try {
            userId = AuthUtil.getUserId(getRequest().getSession());
        } catch (GeneralSecurityException ex) {
            handleException(ex);
            return;
        }

        if (publicKey == null || StringUtils.isBlank(publicKey.getKeyNm())) {
            addFieldError("publicKey.keyNm", REQUIRED);
        }

        try {
            if (publicKey != null) {
                if (existingKeyId != null) {
                    publicKey.setPublicKey(PublicKeyDB.getPublicKey(existingKeyId).getPublicKey());
                } else if ("true".equals(AppConfig.getProperty("forceUserKeyGeneration"))) {
                    validateAndGenerateKey(userId);
                }
                validatePublicKey(userId);
            }

            if (!this.getFieldErrors().isEmpty()) {
                reloadUserKeyViewData(userId);
            }
        } catch (SQLException | GeneralSecurityException ex) {
            handleException(ex);
        }
    }

    private void validateAndGenerateKey(Long userId) throws ServletException, SQLException, GeneralSecurityException {
        if (StringUtils.isBlank(publicKey.getPassphrase())) {
            addFieldError("publicKey.passphrase", REQUIRED);
        } else if (StringUtils.isBlank(publicKey.getPassphraseConfirm())) {
            addFieldError("publicKey.passphraseConfirm", REQUIRED);
        } else if (!publicKey.getPassphrase().equals(publicKey.getPassphraseConfirm())) {
            addError("Passphrases do not match");
        } else if (!PasswordUtil.isValid(publicKey.getPassphrase())) {
            addError(PasswordUtil.PASSWORD_REQ_ERROR_MSG);
        } else {
            publicKey.setPublicKey(generateUserKey(
                    UserDB.getUser(userId).getUsername(),
                    publicKey.getKeyNm(),
                    publicKey.getKeyType()
            ));
        }
    }

    private void validatePublicKey(Long userId) throws ServletException, SQLException, GeneralSecurityException {
        if (StringUtils.isBlank(publicKey.getPublicKey())) {
            addFieldError(PUBLIC_KEY_PUBLIC_KEY, REQUIRED);
        } else if (SSHUtil.getFingerprint(publicKey.getPublicKey()) == null ||
                SSHUtil.getKeyType(publicKey.getPublicKey()) == null) {
            addFieldError(PUBLIC_KEY_PUBLIC_KEY, INVALID);
        } else if (PublicKeyDB.isKeyDisabled(SSHUtil.getFingerprint(publicKey.getPublicKey()))) {
            addError("This key has been disabled. Please generate and set a new public key.");
            addFieldError(PUBLIC_KEY_PUBLIC_KEY, INVALID);
        } else if (PublicKeyDB.isKeyRegistered(userId, publicKey)) {
            addError("This key has already been registered under the selected profile.");
            addFieldError(PUBLIC_KEY_PUBLIC_KEY, INVALID);
        }
    }


    /* ------------------------- Key Generation ------------------------- */

    public String generateUserKey(String username, String keyname, String userSelectedKeyType) throws ServletException {
        int type;
        String keyType;

        if (SSHUtil.ALLOW_USER_KEY_TYPE_SELECTION && StringUtils.isNotEmpty(userSelectedKeyType)) {
            keyType = userSelectedKeyType.toLowerCase();
        } else {
            keyType = SSHUtil.DEFAULT_USER_KEY_TYPE.toLowerCase();
        }

        switch (keyType) {
            case "ecdsa":
                type = KeyPair.ECDSA;
                break;
            case "rsa":
                type = KeyPair.RSA;
                break;
            case "ed448":
                type = KeyPair.ED448;
                break;
            default:
                type = KeyPair.ED25519;
        }

        JSch jsch = new JSch();
        String pubKey;

        try {
            if (type == KeyPair.ED25519 || type == KeyPair.ED448) {
                String algorithm = (type == KeyPair.ED25519) ? "Ed25519" : "Ed448";
                java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(algorithm);
                java.security.KeyPair kp = kpg.generateKeyPair();

                byte[] pubBytes = kp.getPublic().getEncoded();
                String sshKeyType = (type == KeyPair.ED25519) ? "ssh-ed25519" : "ssh-ed448";
                String base64Pub = Base64.getEncoder().encodeToString(SSHUtil.encodeSSHPublicKey(sshKeyType, pubBytes));
                pubKey = sshKeyType + " " + base64Pub + " " + username + "@" + keyname;

                // Build an OpenSSH private key (unencrypted), then rewrap with ssh-keygen if passphrase provided
                Long userId = AuthUtil.getUserId(getRequest().getSession());
                String passphrase = publicKey.getPassphrase();
                String privateKeyPEM = SSHUtil.buildOpenSSHPrivateKey(userId, kp, type, passphrase);

                // Store (internally encrypted for session)
                getRequest().getSession().setAttribute(PVT_KEY, EncryptionUtil.encrypt(privateKeyPEM));
            } else {
                KeyPair keyPair = KeyPair.genKeyPair(jsch, type, SSHUtil.KEY_LENGTH);

                ByteArrayOutputStream privOs = new ByteArrayOutputStream();
                keyPair.writePrivateKey(privOs, publicKey.getPassphrase().getBytes());
                getRequest().getSession().setAttribute(PVT_KEY, EncryptionUtil.encrypt(privOs.toString()));

                ByteArrayOutputStream pubOs = new ByteArrayOutputStream();
                keyPair.writePublicKey(pubOs, username + "@" + keyname);
                pubKey = pubOs.toString();

                keyPair.dispose();
            }
        } catch (Exception ex) {
            handleException(ex);
            return null;
        }

        return pubKey;
    }



    public String generateUserKey(String username, String keyname) throws ServletException {
        return generateUserKey(username, keyname, null);
    }

    /* ------------------------- Utility ------------------------- */

    private void distributePublicKeys(PublicKey publicKey) {
        if (publicKey.getProfile() != null && publicKey.getProfile().getId() != null) {
            RefreshAuthKeyUtil.refreshProfileSystems(publicKey.getProfile().getId());
        } else {
            RefreshAuthKeyUtil.refreshAllSystems();
        }
    }

    private void reloadKeyViewData() throws SQLException, GeneralSecurityException {
        profileList = ProfileDB.getAllProfiles();
        userList = UserDB.getUserSet(new SortedSet(SessionAuditDB.SORT_BY_USERNAME)).getItemList();
        sortedSet = PublicKeyDB.getPublicKeySet(sortedSet);
    }

    private void reloadUserKeyViewData(Long userId) throws SQLException, GeneralSecurityException {
        String userType = AuthUtil.getUserType(getRequest().getSession());
        profileList = Auth.MANAGER.equals(userType)
                ? ProfileDB.getAllProfiles()
                : UserProfileDB.getProfilesByUser(userId);
        sortedSet = PublicKeyDB.getPublicKeySet(sortedSet, userId);
        userPublicKeyList = PublicKeyDB.getUniquePublicKeysForUser(userId);
    }

    private void handleException(Exception ex) throws ServletException {
        log.error(ex.toString(), ex);
        throw new ServletException(ex.toString(), ex);
    }
}
