/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

/**
 * The directory or identity provider could not be asked - unreachable, misconfigured, or
 * failing - as opposed to answering that the credentials are wrong. Kept apart from a
 * rejected login so it reaches the logs as an error and the user as "unavailable": when every
 * failure looked like a wrong password, LDAP login stayed broken for every user across several
 * releases.
 */
public class ExternalAuthException extends Exception {

    public ExternalAuthException(String message) {
        super(message);
    }

    public ExternalAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
