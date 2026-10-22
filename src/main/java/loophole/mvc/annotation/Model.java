/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)

public @interface Model {
    String name();

    /**
     * The request parameters this field accepts, each by the full name a form or link sends:
     * {@code "password"} for a scalar or list field, {@code "user.firstNm"} for one property
     * of a model object, {@code "sortedSet.filterMap"} for every key of a map
     * ({@code sortedSet.filterMap['profile']}).
     * <p>
     * Empty - the default - makes the field output only: the controller sets it for the view
     * and no request parameter is ever bound into it. Binding used to be the default, with
     * every field of every model object reachable by name, so a form posting
     * {@code user.firstNm} equally accepted {@code user.userType} or {@code user.authToken},
     * and output such as the Settings page's public key could be replaced from the query
     * string. Listing each parameter keeps what a request can set down to what the forms
     * actually send.
     */
    String[] params() default {};
}

