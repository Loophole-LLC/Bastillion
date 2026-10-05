/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.util;

import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

/**
 * Prepares untrusted values for inclusion in an audit log line.
 * <p>
 * The login audit log is a flat one-event-per-line file, and its lines are assembled by
 * concatenating request-supplied values - the submitted username above all, which is
 * attacker-controlled and needs no credentials to set. A value containing a newline
 * therefore does not just look odd in the log, it ends the line: a username of
 * {@code "x\nadmin (10.0.0.1) - Authentication Success"} appends a second, entirely
 * fabricated audit record indistinguishable from a real one. For a host whose purpose is
 * recording who reached which system, forged entries are the part that matters.
 */
public class AuditLogUtil {

    /**
     * Any control character, which covers CR and LF (new records) and the escape character
     * (terminal control sequences, for anyone reading the log with cat or less).
     */
    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");

    /**
     * Enough for a long username while keeping a single oversized field from dominating the
     * log - the submitted username is unbounded.
     */
    private static final int MAX_FIELD_LENGTH = 256;

    private AuditLogUtil() {
    }

    /**
     * @param value untrusted value destined for an audit log line
     * @return the value with control characters replaced and its length capped, or "-" if it
     * is empty, so an absent field cannot be mistaken for the next one along
     */
    public static String safe(String value) {
        if (StringUtils.isEmpty(value)) {
            return "-";
        }
        String sanitized = CONTROL_CHARS.matcher(value).replaceAll("?");
        return StringUtils.abbreviate(sanitized, MAX_FIELD_LENGTH);
    }
}
