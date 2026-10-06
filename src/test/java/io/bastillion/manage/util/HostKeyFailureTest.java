/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.JSchException;
import io.bastillion.manage.model.HostSystem;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A refused host key used to be reported as GENERICFAIL, which the systems list renders as
 * just "Failed" - indistinguishable from a dead port, a bad password or a DNS failure, with
 * nothing pointing at the screen that resolves it.
 */
class HostKeyFailureTest {

    /**
     * JSch's host key exceptions have package-private constructors, so they are built
     * reflectively rather than by subclassing them (which the same restriction prevents).
     */
    private static Exception hostKeyException(String simpleName, String message) throws Exception {
        Class<?> type = Class.forName("com.jcraft.jsch." + simpleName);
        java.lang.reflect.Constructor<?> ctor = type.getDeclaredConstructor(String.class);
        ctor.setAccessible(true);
        return (Exception) ctor.newInstance(message);
    }

    private static HostSystem recordFailure(Exception ex) throws Exception {
        Method m = SSHUtil.class.getDeclaredMethod("recordFailure", HostSystem.class, Exception.class);
        m.setAccessible(true);
        HostSystem hostSystem = new HostSystem();
        hostSystem.setStatusCd(HostSystem.SUCCESS_STATUS);
        m.invoke(null, hostSystem, ex);
        return hostSystem;
    }

    @Test
    void anUnknownHostKeyIsReportedAsAHostKeyFailure() throws Exception {
        HostSystem hostSystem = recordFailure(
                hostKeyException("JSchUnknownHostKeyException", "UnknownHostKey: web01"));

        assertEquals(HostSystem.HOST_KEY_FAIL_STATUS, hostSystem.getStatusCd());
        assertTrue(hostSystem.getErrorMsg().contains("Host Keys"), hostSystem.getErrorMsg());
    }

    @Test
    void aChangedHostKeyIsReportedAsAHostKeyFailure() throws Exception {
        HostSystem hostSystem = recordFailure(
                hostKeyException("JSchChangedHostKeyException", "HostKey has been changed: web01"));

        assertEquals(HostSystem.HOST_KEY_FAIL_STATUS, hostSystem.getStatusCd());
    }

    @Test
    void aRevokedHostKeyIsReportedAsAHostKeyFailure() throws Exception {
        HostSystem hostSystem = recordFailure(
                hostKeyException("JSchRevokedHostKeyException", "revoked"));

        assertEquals(HostSystem.HOST_KEY_FAIL_STATUS, hostSystem.getStatusCd());
    }

    @Test
    void aHostKeyFailureWrappedByTheConnectCallIsStillRecognized() throws Exception {
        // Session.connect wraps the cause, so the type has to be looked for down the chain
        // rather than only on the exception that surfaced.
        HostSystem hostSystem = recordFailure(new JSchException("session is down",
                hostKeyException("JSchUnknownHostKeyException", "UnknownHostKey: web01")));

        assertEquals(HostSystem.HOST_KEY_FAIL_STATUS, hostSystem.getStatusCd());
    }

    @Test
    void anythingElseStaysAGenericFailureWithItsOwnMessage() throws Exception {
        HostSystem hostSystem = recordFailure(new JSchException("Connection refused"));

        assertEquals(HostSystem.GENERIC_FAIL_STATUS, hostSystem.getStatusCd());
        assertEquals("Connection refused", hostSystem.getErrorMsg());
    }

    @Test
    void aCyclicCauseChainTerminates() throws Exception {
        // The JVM refuses an exception that causes itself, but a two-element cycle is
        // perfectly constructible and would spin a naive getCause() walk forever.
        JSchException inner = new JSchException("inner");
        JSchException outer = new JSchException("outer", inner);
        inner.initCause(outer);

        assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () ->
                assertEquals(HostSystem.GENERIC_FAIL_STATUS, recordFailure(outer).getStatusCd()));
    }
}
