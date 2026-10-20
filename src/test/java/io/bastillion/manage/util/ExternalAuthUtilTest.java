/**
 * Copyright (C) 2017 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.manage.model.Auth;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * ExternalAuthUtil.login() is fully gated behind externalAuthEnabled - a boolean baked in at
 * class-load time from the bundled jaasModule default (empty, i.e. LDAP disabled), so it's
 * false for this whole test JVM. That's actually the realistic "LDAP not configured" case and
 * the one worth pinning down: login() must be a safe no-op (no LoginContext/JAAS/DB
 * interaction of any kind, no exception) for any input while the module is unconfigured -
 * confirmed here by *not* mocking AuthDB/UserDB/DBUtils at all, so a real call to any of them
 * would fail loudly instead of silently passing.
 *
 * The LDAP-enabled path itself runs against an in-memory directory in
 * ExternalAuthUtilLdapTest, and account linking in ExternalAccountUtilTest. getAllRoles(),
 * the one self-contained piece of LDAP-adjacent logic that only needs a JNDI DirContext, is
 * covered directly via reflection since it's private.
 */
@ExtendWith(MockitoExtension.class)
class ExternalAuthUtilTest {

    @Mock
    private DirContext dirContext;

    @SuppressWarnings("unchecked")
    private static List<String> getAllRoles(DirContext dirContext, String roleBaseDn,
                                             String roleNameAttribute, String roleObjectClass) throws Exception {
        Method method = ExternalAuthUtil.class.getDeclaredMethod("getAllRoles",
                DirContext.class, String.class, String.class, String.class);
        method.setAccessible(true);
        return (List<String>) method.invoke(null, dirContext, roleBaseDn, roleNameAttribute, roleObjectClass);
    }

    @SuppressWarnings("unchecked")
    private static NamingEnumeration<SearchResult> enumerationOf(SearchResult... results) {
        NamingEnumeration<SearchResult> enumeration = org.mockito.Mockito.mock(NamingEnumeration.class);
        if (results.length == 0) {
            when(enumeration.hasMoreElements()).thenReturn(false);
            return enumeration;
        }
        Boolean[] hasMore = new Boolean[results.length + 1];
        for (int i = 0; i < results.length; i++) {
            hasMore[i] = true;
        }
        hasMore[results.length] = false;
        when(enumeration.hasMoreElements()).thenReturn(hasMore[0],
                java.util.Arrays.copyOfRange(hasMore, 1, hasMore.length));
        when(enumeration.nextElement()).thenReturn(results[0],
                java.util.Arrays.copyOfRange(results, 1, results.length));
        return enumeration;
    }

    private static SearchResult resultWithRoleAttribute(String attrName, String... values) throws Exception {
        SearchResult result = org.mockito.Mockito.mock(SearchResult.class);
        Attributes attributes = org.mockito.Mockito.mock(Attributes.class);
        when(result.getAttributes()).thenReturn(attributes);

        if (values.length == 0) {
            when(attributes.get(attrName)).thenReturn(null);
            return result;
        }
        Attribute attribute = org.mockito.Mockito.mock(Attribute.class);
        when(attributes.get(attrName)).thenReturn(attribute);
        // Raw type: Attribute.getAll() returns NamingEnumeration<?>, which a concretely
        // typed mock can't satisfy due to wildcard capture.
        NamingEnumeration valuesEnum = org.mockito.Mockito.mock(NamingEnumeration.class);
        Boolean[] hasMore = new Boolean[values.length + 1];
        for (int i = 0; i < values.length; i++) {
            hasMore[i] = true;
        }
        hasMore[values.length] = false;
        when(valuesEnum.hasMore()).thenReturn(hasMore[0],
                java.util.Arrays.copyOfRange(hasMore, 1, hasMore.length));
        when(valuesEnum.next()).thenReturn(values[0], (Object[]) java.util.Arrays.copyOfRange(values, 1, values.length));
        when(attribute.getAll()).thenReturn(valuesEnum);
        return result;
    }

    @Test
    void loginIsANoOpForAnyInputWhenLdapIsNotConfigured() throws Exception {
        assertNull(ExternalAuthUtil.login(null));

        Auth blank = new Auth();
        assertNull(ExternalAuthUtil.login(blank));

        Auth full = new Auth();
        full.setUsername("alice");
        full.setPassword("hunter2");
        assertNull(ExternalAuthUtil.login(full));
    }

    @Test
    void getAllRolesCollectsEveryValueOfAMultiValuedRoleAttribute() throws Exception {
        // Built and fully stubbed *before* the outer when(...).thenReturn(...) - nesting a
        // when()/thenReturn() pair inside another one's argument list corrupts Mockito's
        // stubbing state (it briefly "steals" the outer when() call's pending stub).
        SearchResult result = resultWithRoleAttribute("cn", "role-a", "role-b");
        NamingEnumeration<SearchResult> results = enumerationOf(result);
        when(dirContext.search(anyString(), anyString(), any(Object[].class), any(SearchControls.class)))
                .thenReturn(results);

        List<String> roles = getAllRoles(dirContext, "ou=roles,dc=example,dc=com", "cn", "groupOfNames");

        assertEquals(List.of("role-a", "role-b"), roles);
    }

    @Test
    void getAllRolesAggregatesAcrossMultipleSearchResults() throws Exception {
        SearchResult first = resultWithRoleAttribute("cn", "role-a");
        SearchResult second = resultWithRoleAttribute("cn", "role-b");
        NamingEnumeration<SearchResult> results = enumerationOf(first, second);
        when(dirContext.search(anyString(), anyString(), any(Object[].class), any(SearchControls.class)))
                .thenReturn(results);

        List<String> roles = getAllRoles(dirContext, "ou=roles,dc=example,dc=com", "cn", "groupOfNames");

        assertEquals(List.of("role-a", "role-b"), roles);
    }

    @Test
    void getAllRolesSkipsResultsMissingTheRoleAttributeWithoutThrowing() throws Exception {
        SearchResult result = resultWithRoleAttribute("cn");
        NamingEnumeration<SearchResult> results = enumerationOf(result);
        when(dirContext.search(anyString(), anyString(), any(Object[].class), any(SearchControls.class)))
                .thenReturn(results);

        List<String> roles = getAllRoles(dirContext, "ou=roles,dc=example,dc=com", "cn", "groupOfNames");

        assertTrue(roles.isEmpty());
    }

    @Test
    void getAllRolesReturnsEmptyListWhenSearchHasNoResults() throws Exception {
        NamingEnumeration<SearchResult> results = enumerationOf();
        when(dirContext.search(anyString(), anyString(), any(Object[].class), any(SearchControls.class)))
                .thenReturn(results);

        List<String> roles = getAllRoles(dirContext, "ou=roles,dc=example,dc=com", "cn", "groupOfNames");

        assertTrue(roles.isEmpty());
    }
}
