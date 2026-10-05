/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The forwarded-for header is the login throttle's key and an audit log field, so what is
 * taken out of it decides whether the throttle can be bypassed by varying the header.
 */
class ClientIPAddressTest {

    @Test
    void takesTheClientAddressFromAForwardedChain() {
        // Each hop appends, so even behind a trusted proxy the raw value carries a
        // client-supplied prefix. Using the whole string as the throttle key made every
        // request its own key.
        assertEquals("203.0.113.7", AuthUtil.firstForwardedAddress("203.0.113.7, 10.0.0.1, 10.0.0.2"));
    }

    @Test
    void acceptsASingleAddress() {
        assertEquals("203.0.113.7", AuthUtil.firstForwardedAddress("203.0.113.7"));
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertEquals("203.0.113.7", AuthUtil.firstForwardedAddress("  203.0.113.7 , 10.0.0.1"));
    }

    @Test
    void acceptsAnIpv6Address() {
        assertEquals("2001:db8::1", AuthUtil.firstForwardedAddress("2001:db8::1, 10.0.0.1"));
    }

    @Test
    void unwrapsABracketedIpv6AddressWithAPort() {
        assertEquals("2001:db8::1", AuthUtil.firstForwardedAddress("[2001:db8::1]:443"));
    }

    @Test
    void rejectsAValueThatIsNotAnAddress() {
        // Falls back to the TCP peer address rather than keying the throttle, or an audit
        // line, on arbitrary header text.
        assertNull(AuthUtil.firstForwardedAddress("not-an-ip"));
        assertNull(AuthUtil.firstForwardedAddress("evil.example.com"));
        assertNull(AuthUtil.firstForwardedAddress("999.999.999.999"));
    }

    @Test
    void rejectsAnEmptyOrAbsentHeader() {
        assertNull(AuthUtil.firstForwardedAddress(""));
        assertNull(AuthUtil.firstForwardedAddress(null));
    }

    @Test
    void rejectsAnOverlongValue() {
        assertNull(AuthUtil.firstForwardedAddress("1".repeat(200)));
    }
}
