/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.annotation;

public enum MethodType {
    GET("GET"), POST("POST"), PUT("PUT"), DELETE("DELETE"), PATCH("PATCH"), HEAD("HEAD"), OPTIONS("OPTIONS");

    private String method;

    MethodType(String method) {
        this.method = method;
    }

    public String toString() {
        return method;
    }

}
