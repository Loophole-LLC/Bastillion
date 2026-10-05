/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.util;

import org.apache.commons.lang3.StringUtils;

import java.util.Comparator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-memory per-client-IP throttle for failed login attempts.
 * <p>
 * Deliberately keyed by client IP rather than username - a per-account lockout would let
 * anyone remotely lock out a known admin username by deliberately submitting the wrong
 * password for it. Tracking by IP instead slows down credential guessing without giving an
 * attacker a way to deny service to a legitimate user's account.
 */
public class LoginThrottleUtil {

    private static final int MAX_ATTEMPTS =
            Integer.parseInt(AppConfig.getProperty("maxLoginAttemptsPerIP", "10"));
    private static final long WINDOW_MILLIS =
            Long.parseLong(AppConfig.getProperty("loginThrottleWindowMinutes", "5")) * 60_000L;

    /**
     * Hard ceiling on tracked IPs.
     * <p>
     * Entries were only ever removed when that same IP came back - a successful login, or a
     * later attempt that found the window expired. Nothing swept the ones that never
     * returned, so a spray of failed logins from many distinct sources (trivial over IPv6,
     * or through a forwarded-for header) grew this map for the lifetime of the process.
     */
    private static final int MAX_TRACKED_IPS =
            Integer.parseInt(AppConfig.getProperty("maxThrottledIPs", "20000"));

    private static final ConcurrentHashMap<String, Window> ATTEMPTS = new ConcurrentHashMap<>();

    private LoginThrottleUtil() {
    }

    private static class Window {
        final long windowStart = System.currentTimeMillis();
        final AtomicInteger count = new AtomicInteger(0);

        boolean isExpired() {
            return System.currentTimeMillis() - windowStart > WINDOW_MILLIS;
        }
    }

    /**
     * true if this IP has exceeded the allowed failed login attempts within the current window
     *
     * @param clientIP client IP address
     * @return true if further login attempts from this IP should be refused for now
     */
    public static boolean isBlocked(String clientIP) {
        if (StringUtils.isEmpty(clientIP)) {
            return false;
        }
        Window window = ATTEMPTS.get(clientIP);
        if (window == null) {
            return false;
        }
        if (window.isExpired()) {
            ATTEMPTS.remove(clientIP, window);
            return false;
        }
        return window.count.get() >= MAX_ATTEMPTS;
    }

    /**
     * record a failed login attempt from this IP
     *
     * @param clientIP client IP address
     */
    public static void recordFailure(String clientIP) {
        if (StringUtils.isEmpty(clientIP)) {
            return;
        }
        if (ATTEMPTS.size() >= MAX_TRACKED_IPS && !ATTEMPTS.containsKey(clientIP)) {
            evictToMakeRoom();
        }
        ATTEMPTS.compute(clientIP, (ip, window) -> {
            if (window == null || window.isExpired()) {
                window = new Window();
            }
            window.count.incrementAndGet();
            return window;
        });
    }

    /**
     * Drops expired windows, and if that frees nothing, the oldest window.
     * <p>
     * Every window expires within WINDOW_MILLIS, so sweeping almost always recovers space;
     * the cap only binds when more than MAX_TRACKED_IPS distinct addresses fail inside a
     * single window, which is the attack rather than normal use. Evicting the oldest rather
     * than refusing to track the new address keeps that from becoming a way to pin the map
     * full of junk and then guess passwords from an untracked address.
     */
    private static void evictToMakeRoom() {
        ATTEMPTS.values().removeIf(Window::isExpired);
        if (ATTEMPTS.size() < MAX_TRACKED_IPS) {
            return;
        }
        ATTEMPTS.entrySet().stream()
                .min(Comparator.comparingLong(entry -> entry.getValue().windowStart))
                .ifPresent(oldest -> ATTEMPTS.remove(oldest.getKey(), oldest.getValue()));
    }

    /**
     * clear any tracked failures for this IP following a successful login
     *
     * @param clientIP client IP address
     */
    public static void recordSuccess(String clientIP) {
        if (StringUtils.isNotEmpty(clientIP)) {
            ATTEMPTS.remove(clientIP);
        }
    }
}
