/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * SamlAuthUtil.login() is fully gated behind samlAuthEnabled - a boolean baked in at
 * class-load time from the bundled samlIdpMetadataUrl/samlIdpSsoUrl defaults (both empty,
 * i.e. SAML disabled), so it's false for this whole test JVM. Mirrors
 * ExternalAuthUtilTest's approach for the LDAP-disabled case: login() must be a safe no-op
 * (no assertion parsing, no DB interaction) for any input while SAML is unconfigured -
 * confirmed by never stubbing the request beyond what's needed to prove it's untouched.
 *
 * The SAML-enabled path (assertion signature/condition validation, NameID extraction, role-
 * claim mapping, JIT provisioning) needs a real signed assertion fixture and a matching
 * Saml2Settings/IdP certificate to exercise meaningfully - not covered here.
 */
@ExtendWith(MockitoExtension.class)
class SamlAuthUtilTest {

    @Mock
    private HttpServletRequest request;

    @Test
    void loginIsANoOpForAnyInputWhenSamlIsNotConfigured() throws Exception {
        assertNull(SamlAuthUtil.login(null));
        assertNull(SamlAuthUtil.login(request));

        //disabled-fast-path returns before the request is ever dereferenced
        verifyNoInteractions(request);
    }
}
