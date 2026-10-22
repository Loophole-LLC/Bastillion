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
@Target(ElementType.METHOD)

public @interface Validate {
    String input();
}

