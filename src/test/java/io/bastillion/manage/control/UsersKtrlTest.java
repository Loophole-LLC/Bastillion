/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.UserDB;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.SortedSet;
import io.bastillion.manage.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class UsersKtrlTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private UsersKtrl validated(String userType, String authType) throws Exception {
        User user = new User();
        user.setUsername("someone");
        user.setFirstNm("Some");
        user.setLastNm("One");
        user.setUserType(userType);
        user.setAuthType(authType);
        user.setPassword("Valid-Pw-9!");
        user.setPasswordConfirm("Valid-Pw-9!");

        UsersKtrl ktrl = new UsersKtrl(request, response);
        Field field = UsersKtrl.class.getDeclaredField("user");
        field.setAccessible(true);
        field.set(ktrl, user);

        try (MockedStatic<UserDB> userDb = mockStatic(UserDB.class);
             MockedStatic<AuthUtil> authUtil = mockStatic(AuthUtil.class)) {
            userDb.when(() -> UserDB.isUnique(any(), any())).thenReturn(true);
            userDb.when(() -> UserDB.getUserSet(any())).thenReturn(new SortedSet());
            ktrl.validateSaveUser();
        }
        return ktrl;
    }

    @Test
    void aUserTypeOtherThanAdministratorOrManagerIsRefused() throws Exception {
        // It used to be stored as given: neither manager nor administrator access, yet listed
        // as "Full Access" and left out of every profile's user list.
        assertEquals("Invalid", validated("X", Auth.AUTH_BASIC).getFieldErrors().get("user.userType"));
        assertEquals("Invalid", validated(null, Auth.AUTH_BASIC).getFieldErrors().get("user.userType"));
    }

    @Test
    void anUnknownAuthTypeIsRefused() throws Exception {
        assertEquals("Invalid", validated(Auth.ADMINISTRATOR, "X").getFieldErrors().get("user.authType"));
    }

    @Test
    void theTypesTheFormOffersAreAccepted() throws Exception {
        for (String userType : new String[]{Auth.ADMINISTRATOR, Auth.MANAGER}) {
            for (String authType : new String[]{Auth.AUTH_BASIC, Auth.AUTH_EXTERNAL, Auth.AUTH_SAML}) {
                UsersKtrl ktrl = validated(userType, authType);
                assertNull(ktrl.getFieldErrors().get("user.userType"), userType);
                assertNull(ktrl.getFieldErrors().get("user.authType"), authType);
                assertFalse(ktrl.hasErrors(), userType + "/" + authType + " " + ktrl.getFieldErrors() + ktrl.getErrors());
            }
        }
    }
}
