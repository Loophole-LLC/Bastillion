/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.manage.db.PublicKeyDB;
import io.bastillion.manage.db.UserProfileDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.Profile;
import io.bastillion.manage.model.PublicKey;
import io.bastillion.manage.util.EncryptionUtil;
import io.bastillion.manage.util.OpenSSHKeyUtil;
import io.bastillion.manage.util.RefreshAuthKeyUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AuthKeysKtrl is where SSH public/private keys get generated, validated, and handed out.
 * Two properties matter most: (1) downloadPvtKey is a one-shot download - the session's
 * private key attribute must be cleared whether or not a download actually happened, so a
 * stolen/replayed session cookie can't re-download a key already handed out; (2) a non-
 * manager can only save a key against a profile they actually belong to -
 * UserProfileDB.checkIsUsersProfile is the whole enforcement of that boundary.
 */
@ExtendWith(MockitoExtension.class)
class AuthKeysKtrlTest {

    private static final String PVT_KEY_SESSION_ATTR = "privateKey";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private AuthKeysKtrl newController() {
        AuthKeysKtrl ktrl = new AuthKeysKtrl(request, response);
        lenient().when(request.getSession()).thenReturn(session);
        return ktrl;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        java.lang.reflect.Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static String edEncodedPublicKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        byte[] encoded = OpenSSHKeyUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded());
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(encoded) + " test@bastillion";
    }

    // ---- downloadPvtKey: one-shot download ------------------------------------------------

    @Test
    void downloadPvtKeyWritesTheFileThenClearsTheSessionAttribute() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute(PVT_KEY_SESSION_ATTR))
                .thenReturn(EncryptionUtil.encrypt("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"));

        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("my-key");
        setField(ktrl, "publicKey", publicKey);

        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(
                new jakarta.servlet.ServletOutputStream() {
                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(jakarta.servlet.WriteListener writeListener) {
                    }

                    @Override
                    public void write(int b) {
                        captured.write(b);
                    }
                });

        String view = ktrl.downloadPvtKey();

        assertNull(view);
        verify(response).setHeader("Content-Disposition", "attachment;filename=my-key.key");
        assertTrue(captured.toString().contains("BEGIN PRIVATE KEY"));
        verify(session).removeAttribute(PVT_KEY_SESSION_ATTR);
    }

    @Test
    void downloadPvtKeyWithNothingInSessionWritesNothingButStillClearsTheAttribute() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute(PVT_KEY_SESSION_ATTR)).thenReturn(null);

        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("my-key");
        setField(ktrl, "publicKey", publicKey);

        ktrl.downloadPvtKey();

        verify(response, never()).getOutputStream();
        verify(session).removeAttribute(PVT_KEY_SESSION_ATTR);
    }

    // ---- savePublicKeys: profile-ownership authorization boundary -------------------------

    @Test
    void managerCanSaveAKeyAgainstAnyProfile() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));
        when(session.getAttribute("userType")).thenReturn("M");

        Profile profile = new Profile();
        profile.setId(99L);
        PublicKey publicKey = new PublicKey();
        publicKey.setId(null);
        publicKey.setProfile(profile);
        publicKey.setKeyNm("k");
        setField(ktrl, "publicKey", publicKey);
        setField(ktrl, "sortedSet", new io.bastillion.manage.model.SortedSet());

        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class);
             MockedStatic<RefreshAuthKeyUtil> refreshUtil = mockStatic(RefreshAuthKeyUtil.class)) {

            ktrl.savePublicKeys();

            publicKeyDB.verify(() -> PublicKeyDB.insertPublicKey(publicKey));
            // A manager never needs the profile-ownership check at all.
            userProfileDB.verify(() -> UserProfileDB.checkIsUsersProfile(anyLong(), anyLong()), never());
        }
    }

    @Test
    void nonManagerCannotSaveAKeyAgainstAProfileTheyDontOwn() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("2"));
        when(session.getAttribute("userType")).thenReturn("A");

        Profile profile = new Profile();
        profile.setId(99L);
        PublicKey publicKey = new PublicKey();
        publicKey.setProfile(profile);
        publicKey.setKeyNm("k");
        setField(ktrl, "publicKey", publicKey);
        setField(ktrl, "sortedSet", new io.bastillion.manage.model.SortedSet());

        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class);
             MockedStatic<RefreshAuthKeyUtil> refreshUtil = mockStatic(RefreshAuthKeyUtil.class)) {
            userProfileDB.when(() -> UserProfileDB.checkIsUsersProfile(2L, 99L)).thenReturn(false);

            ktrl.savePublicKeys();

            publicKeyDB.verify(() -> PublicKeyDB.insertPublicKey(any()), never());
            publicKeyDB.verify(() -> PublicKeyDB.updatePublicKey(any()), never());
        }
    }

    @Test
    void nonManagerCanSaveAKeyAgainstTheirOwnProfile() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("2"));
        when(session.getAttribute("userType")).thenReturn("A");

        Profile profile = new Profile();
        profile.setId(99L);
        PublicKey publicKey = new PublicKey();
        publicKey.setProfile(profile);
        publicKey.setKeyNm("k");
        setField(ktrl, "publicKey", publicKey);
        setField(ktrl, "sortedSet", new io.bastillion.manage.model.SortedSet());

        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class);
             MockedStatic<RefreshAuthKeyUtil> refreshUtil = mockStatic(RefreshAuthKeyUtil.class)) {
            userProfileDB.when(() -> UserProfileDB.checkIsUsersProfile(2L, 99L)).thenReturn(true);

            ktrl.savePublicKeys();

            publicKeyDB.verify(() -> PublicKeyDB.insertPublicKey(publicKey));
        }
    }

    // ---- validatePublicKey: pure validation branches ---------------------------------------
    // forceUserKeyGeneration=true in the bundled defaults, so validateSavePublicKeys() also
    // runs validateAndGenerateKey() first. Passphrase is left unset in these tests, which
    // stops at its first branch (a passphrase field error) without touching
    // publicKey.publicKey - so it doesn't interfere with isolating validatePublicKey's own
    // branches below.

    @Test
    void validateRejectsABlankKey() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));

        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("k");
        publicKey.setPublicKey("");
        setField(ktrl, "publicKey", publicKey);

        // Any field error triggers reloadUserKeyViewData(), which re-fetches profile/key
        // lists to re-render the form - stub those DAOs out so it doesn't hit the real
        // (schema-less in this test JVM) DB.
        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<io.bastillion.manage.db.ProfileDB> profileDB = mockStatic(io.bastillion.manage.db.ProfileDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class)) {

            ktrl.validateSavePublicKeys();

            assertEquals("Required", ktrl.getFieldErrors().get("publicKey.publicKey"));
        }
    }

    @Test
    void validateRejectsMalformedKeyText() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));

        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("k");
        publicKey.setPublicKey("this-is-not-a-key");
        setField(ktrl, "publicKey", publicKey);

        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<io.bastillion.manage.db.ProfileDB> profileDB = mockStatic(io.bastillion.manage.db.ProfileDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class)) {

            ktrl.validateSavePublicKeys();

            assertEquals("Invalid", ktrl.getFieldErrors().get("publicKey.publicKey"));
        }
    }

    @Test
    void validateRejectsADisabledKey() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));

        String key = edEncodedPublicKey();
        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("k");
        publicKey.setPublicKey(key);
        setField(ktrl, "publicKey", publicKey);

        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<io.bastillion.manage.db.ProfileDB> profileDB = mockStatic(io.bastillion.manage.db.ProfileDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class)) {
            publicKeyDB.when(() -> PublicKeyDB.isKeyDisabled(OpenSSHKeyUtil.getFingerprint(key))).thenReturn(true);

            ktrl.validateSavePublicKeys();

            assertTrue(ktrl.getErrors().stream().anyMatch(e -> e.contains("disabled")));
        }
    }

    @Test
    void validateRejectsAnAlreadyRegisteredKey() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));

        String key = edEncodedPublicKey();
        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("k");
        publicKey.setPublicKey(key);
        setField(ktrl, "publicKey", publicKey);

        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<io.bastillion.manage.db.ProfileDB> profileDB = mockStatic(io.bastillion.manage.db.ProfileDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class)) {
            publicKeyDB.when(() -> PublicKeyDB.isKeyDisabled(OpenSSHKeyUtil.getFingerprint(key))).thenReturn(false);
            publicKeyDB.when(() -> PublicKeyDB.isKeyRegistered(eq(1L), any())).thenReturn(true);

            ktrl.validateSavePublicKeys();

            assertTrue(ktrl.getErrors().stream().anyMatch(e -> e.contains("already been registered")));
        }
    }

    @Test
    void validateAcceptsAWellFormedUnregisteredKey() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));

        String key = edEncodedPublicKey();
        PublicKey publicKey = new PublicKey();
        publicKey.setKeyNm("k");
        publicKey.setPublicKey(key);
        setField(ktrl, "publicKey", publicKey);

        // A passphrase field error is still expected here (forceUserKeyGeneration=true, no
        // passphrase set) - the assertion below is scoped to publicKey.publicKey specifically.
        try (MockedStatic<PublicKeyDB> publicKeyDB = mockStatic(PublicKeyDB.class);
             MockedStatic<io.bastillion.manage.db.ProfileDB> profileDB = mockStatic(io.bastillion.manage.db.ProfileDB.class);
             MockedStatic<UserProfileDB> userProfileDB = mockStatic(UserProfileDB.class)) {
            publicKeyDB.when(() -> PublicKeyDB.isKeyDisabled(OpenSSHKeyUtil.getFingerprint(key))).thenReturn(false);
            publicKeyDB.when(() -> PublicKeyDB.isKeyRegistered(eq(1L), any())).thenReturn(false);

            ktrl.validateSavePublicKeys();

            assertFalse(ktrl.getFieldErrors().containsKey("publicKey.publicKey"));
            assertTrue(ktrl.getErrors().isEmpty());
        }
    }

    // ---- generateUserKey: end-to-end key generation ----------------------------------------

    @Test
    void generateUserKeyEd25519ProducesAWorkingKeyPairAndEncryptsThePrivateKeyIntoSession() throws Exception {
        AuthKeysKtrl ktrl = newController();
        when(session.getAttribute("userId")).thenReturn(EncryptionUtil.encrypt("1"));

        PublicKey publicKey = new PublicKey();
        publicKey.setPassphrase("Str0ng!Passphrase");
        setField(ktrl, "publicKey", publicKey);

        String pub = ktrl.generateUserKey("alice", "alice-key", "ed25519");

        assertNotNull(pub);
        assertTrue(pub.startsWith("ssh-ed25519 "));
        assertNotNull(OpenSSHKeyUtil.getFingerprint(pub));
        verify(session).setAttribute(eq(PVT_KEY_SESSION_ATTR), any());
    }
}
