/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * The login audit log is one event per line, assembled from request-supplied values - the
 * submitted username above all, which needs no credentials to set.
 */
class AuditLogUtilTest {

    @Test
    void stripsTheNewlinesThatWouldForgeASecondAuditRecord() {
        String forged = "x\nadmin (10.0.0.1) - Authentication Success";

        String safe = AuditLogUtil.safe(forged);

        assertFalse(safe.contains("\n"));
        assertEquals("x?admin (10.0.0.1) - Authentication Success", safe);
    }

    @Test
    void stripsCarriageReturnsAndEscapeSequences() {
        assertEquals("??[31mred", AuditLogUtil.safe("\r\u001b[31mred"));
    }

    @Test
    void rendersAnEmptyValueAsAPlaceholder() {
        // So an absent field cannot be mistaken for the next one along.
        assertEquals("-", AuditLogUtil.safe(""));
        assertEquals("-", AuditLogUtil.safe(null));
    }

    @Test
    void capsAnOversizedField() {
        String safe = AuditLogUtil.safe("a".repeat(5000));

        assertEquals(256, safe.length());
    }

    @Test
    void leavesAnOrdinaryUsernameAlone() {
        assertEquals("sean.kavanagh", AuditLogUtil.safe("sean.kavanagh"));
    }
}
