/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.SystemDB;
import io.bastillion.manage.model.Auth;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * These endpoints are reachable by any authenticated account (/admin/* admits both account
 * types), and a POST that simply omits the form fields used to reach a null model object and
 * come back as an HTTP 500 instead of a validation message.
 */
@ExtendWith(MockitoExtension.class)
class UserSettingsKtrlTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private static void set(UserSettingsKtrl ktrl, String name, Object value) throws Exception {
        Field field = UserSettingsKtrl.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(ktrl, value);
    }

    @Test
    void theBoundModelsAreNeverNullSoAParameterlessPostValidatesInsteadOfFailing() {
        UserSettingsKtrl ktrl = new UserSettingsKtrl(request, response);

        // Nothing bound: BaseKontroller only default-constructs a model object when a request
        // parameter names it, so these are what passwordSubmit/themeSubmit see for a POST with
        // no fields at all.
        ktrl.validatePasswordSubmit();

        assertTrue(ktrl.hasErrors());
        assertEquals("Required", ktrl.getFieldErrors().get("auth.password"));
        assertEquals("Required", ktrl.getFieldErrors().get("auth.passwordConfirm"));
        assertEquals("Required", ktrl.getFieldErrors().get("auth.prevPassword"));
    }

    @Test
    void themeSubmitHasAUserSettingsToWriteIntoWithNothingBound() throws Exception {
        // themeSubmit has no @Validate guard, so a POST with no userSettings.* parameters went
        // straight into the method body and dereferenced a null field.
        UserSettingsKtrl ktrl = new UserSettingsKtrl(request, response);

        Field field = UserSettingsKtrl.class.getDeclaredField("userSettings");
        field.setAccessible(true);
        assertNotNull(field.get(ktrl));
    }

    @Test
    void acceptsAFullyPopulatedPasswordChange() throws Exception {
        UserSettingsKtrl ktrl = new UserSettingsKtrl(request, response);
        Auth auth = new Auth();
        auth.setPrevPassword("oldPassword1!");
        auth.setPassword("newPassword1!");
        auth.setPasswordConfirm("newPassword1!");
        set(ktrl, "auth", auth);

        ktrl.validatePasswordSubmit();

        assertFalse(ktrl.hasErrors());
    }

    // --- importAppKeySubmit replaces the application SSH keypair for every managed system ---

    @Test
    void refusesAnApplicationKeyImportWithNoKeyMaterialRatherThanFailing() throws Exception {
        UserSettingsKtrl ktrl = new UserSettingsKtrl(request, response);
        when(request.getSession()).thenReturn(session);

        try (MockedStatic<AuthUtil> authUtil = mockStatic(AuthUtil.class);
             MockedStatic<SystemDB> systemDB = mockStatic(SystemDB.class)) {
            authUtil.when(() -> AuthUtil.getUserType(session)).thenReturn(Auth.MANAGER);
            systemDB.when(SystemDB::getSystemCount).thenReturn(0);

            String forward = ktrl.importAppKeySubmit();

            assertEquals("/admin/user_settings.html", forward);
            assertTrue(ktrl.getErrors().contains("Both the private key and the public key are required"));
        }
    }

    @Test
    void refusesAnApplicationKeyImportFromANonManager() throws Exception {
        // Checked server-side, not just hidden in the UI: /admin/* is reachable by
        // non-manager account types too.
        UserSettingsKtrl ktrl = new UserSettingsKtrl(request, response);
        when(request.getSession()).thenReturn(session);

        try (MockedStatic<AuthUtil> authUtil = mockStatic(AuthUtil.class);
             MockedStatic<SystemDB> systemDB = mockStatic(SystemDB.class)) {
            authUtil.when(() -> AuthUtil.getUserType(session)).thenReturn(Auth.ADMINISTRATOR);
            systemDB.when(SystemDB::getSystemCount).thenReturn(3);

            ktrl.importAppKeySubmit();

            assertTrue(ktrl.getErrors().contains("Only managers can replace the application SSH key"));
        }
    }
}
