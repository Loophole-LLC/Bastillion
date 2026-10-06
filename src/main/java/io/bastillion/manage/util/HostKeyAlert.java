/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import io.bastillion.manage.db.HostKeyDB;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;

/**
 * How many host keys are currently refusing connections, for the navigation badge.
 * <p>
 * A changed host key blocks every connection to that system silently - the operator finds out
 * from a failed session, not from Bastillion. Surfacing the count in the navigation is what
 * turns that into something noticed.
 * <p>
 * Read from the navigation fragment, which renders on every page, so the result is cached
 * briefly and this never throws: a count that cannot be read must not be allowed to take out
 * every page in the application.
 */
public final class HostKeyAlert {

    private static final Logger log = LoggerFactory.getLogger(HostKeyAlert.class);

    /**
     * Long enough that a page load is not a database round trip, short enough that a newly
     * blocked host shows up while the operator is still looking at the screen.
     */
    private static final long CACHE_MILLIS = 30_000;

    private static final AtomicLong CACHED_AT = new AtomicLong(0);
    private static volatile int cachedCount = 0;

    private HostKeyAlert() {
    }

    /**
     * Drops the cached count, so the next read reflects a change that has just been made.
     * <p>
     * Called by {@link HostKeyDB} whenever host key state changes. Without it an operator who
     * had just approved a key would keep seeing the badge for up to {@link #CACHE_MILLIS},
     * which reads as the action not having worked.
     */
    public static void invalidate() {
        CACHED_AT.set(0);
    }

    /**
     * @return the number of recorded host keys in a state that refuses connections (new,
     * changed or revoked), or 0 if it cannot be determined
     */
    public static int blockingCount() {
        long now = System.currentTimeMillis();
        long cachedAt = CACHED_AT.get();
        if (now - cachedAt < CACHE_MILLIS) {
            return cachedCount;
        }
        // A racing caller may recompute too; that is cheaper than holding a lock on the path
        // that renders every page.
        if (!CACHED_AT.compareAndSet(cachedAt, now)) {
            return cachedCount;
        }
        try {
            cachedCount = HostKeyDB.getBlockingCount();
        } catch (Exception ex) {
            log.error("Could not count blocked host keys", ex);
            cachedCount = 0;
        }
        return cachedCount;
    }
}
