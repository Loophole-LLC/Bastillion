/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.JSchException;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The point of the per-system certificate test is telling an operator what to change, so the
 * message matters as much as the pass/fail. The overwhelmingly common failure is a host that
 * was never given TrustedUserCAKeys.
 */
class CertificateTestResultTest {

    private static String explain(Exception ex) throws Exception {
        Method m = SSHUtil.class.getDeclaredMethod("explainCertificateTestFailure", Exception.class);
        m.setAccessible(true);
        return (String) m.invoke(null, ex);
    }

    private static Exception hostKeyException(String simpleName, String message) throws Exception {
        Class<?> type = Class.forName("com.jcraft.jsch." + simpleName);
        java.lang.reflect.Constructor<?> ctor = type.getDeclaredConstructor(String.class);
        ctor.setAccessible(true);
        return (Exception) ctor.newInstance(message);
    }

    @Test
    void aRejectedCertificatePointsAtTrustedUserCAKeys() throws Exception {
        String message = explain(new JSchException("Auth fail for methods 'publickey'"));

        assertTrue(message.contains("TrustedUserCAKeys"), message);
        assertTrue(message.contains("reloaded"), message);
    }

    @Test
    void aRefusedHostKeySaysTheCertificateWasNeverTried() throws Exception {
        // Host key verification happens before authentication, so this is not a certificate
        // problem and must not be reported as one.
        String message = explain(hostKeyException("JSchUnknownHostKeyException", "UnknownHostKey: web01"));

        assertTrue(message.contains("Host Keys"), message);
        assertTrue(message.contains("never tried"), message);
    }

    @Test
    void aDnsFailureIsReportedAsSuch() throws Exception {
        String message = explain(new JSchException("java.net.UnknownHostException: web01"));

        assertTrue(message.toLowerCase().contains("dns"), message);
    }

    @Test
    void anythingElseCarriesItsOwnMessageThrough() throws Exception {
        String message = explain(new JSchException("Connection refused"));

        assertTrue(message.contains("Connection refused"), message);
    }

    @Test
    void aMessagelessFailureStillSaysSomethingUseful() throws Exception {
        String message = explain(new JSchException());

        assertTrue(message.contains("JSchException"), message);
    }
}
