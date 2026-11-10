/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.control;

import com.jcraft.jsch.Session;
import io.bastillion.common.util.AuthUtil;
import io.bastillion.manage.db.SystemStatusDB;
import io.bastillion.manage.model.HostSystem;
import io.bastillion.manage.model.SchSession;
import io.bastillion.manage.model.UserSchSessions;
import io.bastillion.manage.util.SSHUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.fileupload2.core.FileItem;
import org.apache.commons.fileupload2.jakarta.servlet6.JakartaServletFileUpload;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static io.bastillion.common.util.AuthTestSupport.encryptedAttribute;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

/**
 * UPLOAD_PATH is one directory shared by every user. Staged files used to be named after the
 * uploaded file, and push() pushed whichever file the request's uploadFileName named, so one
 * user could push another's staged upload to their own system, overwrite it with their own
 * content before it was pushed, or delete it. Each upload is now staged under a random name
 * held in the uploader's HTTP session, and push() only ever pushes that.
 */
class UploadAndPushKtrlTest {

    private final List<File> created = new ArrayList<>();
    private Map<Long, UserSchSessions> savedSchSessionMap;

    @BeforeEach
    void saveSessionMap() {
        savedSchSessionMap = SecureShellKtrl.getUserSchSessionMap();
        SecureShellKtrl.setUserSchSessionMap(new ConcurrentHashMap<>());
    }

    @AfterEach
    void cleanUp() {
        SecureShellKtrl.setUserSchSessionMap(savedSchSessionMap);
        created.forEach(File::delete);
    }

    /**
     * a signed-in Bastillion session for userId, with working attribute storage
     */
    private static HttpSession signedInSession(long userId, long sessionId) throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(AuthUtil.USER_ID, encryptedAttribute(String.valueOf(userId)));
        attributes.put(AuthUtil.SESSION_ID, encryptedAttribute(String.valueOf(sessionId)));
        HttpSession session = mock(HttpSession.class);
        lenient().when(session.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.<String>getArgument(0)));
        lenient().doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1)))
                .when(session).setAttribute(anyString(), any());
        lenient().doAnswer(i -> attributes.remove(i.<String>getArgument(0)))
                .when(session).removeAttribute(anyString());
        return session;
    }

    private static HttpServletRequest requestFor(HttpSession session) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        lenient().when(request.getSession()).thenReturn(session);
        return request;
    }

    /**
     * runs uploadSubmit() as if fileName had been uploaded with the given content
     */
    private UploadAndPushKtrl upload(HttpSession session, String fileName, String content) throws Exception {
        FileItem item = mock(FileItem.class);
        when(item.isFormField()).thenReturn(false);
        when(item.getName()).thenReturn(fileName);
        when(item.getInputStream()).thenReturn(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));

        UploadAndPushKtrl ktrl = new UploadAndPushKtrl(requestFor(session), mock(HttpServletResponse.class));
        try (MockedConstruction<JakartaServletFileUpload> ignored = mockConstruction(JakartaServletFileUpload.class,
                (m, c) -> when(m.parseRequest(any(HttpServletRequest.class))).thenReturn(List.of(item)));
             MockedStatic<SystemStatusDB> statusDB = mockStatic(SystemStatusDB.class)) {
            statusDB.when(() -> SystemStatusDB.getAllSystemStatus(anyLong())).thenReturn(Collections.emptyList());
            assertEquals("/admin/upload_result.html", ktrl.uploadSubmit());
        }
        UploadAndPushKtrl.StagedUpload staged = staged(session);
        assertNotNull(staged);
        created.add(new File(UploadAndPushKtrl.UPLOAD_PATH, staged.storedName()));
        return ktrl;
    }

    private static UploadAndPushKtrl.StagedUpload staged(HttpSession session) {
        return (UploadAndPushKtrl.StagedUpload) session.getAttribute(UploadAndPushKtrl.STAGED_UPLOAD);
    }

    private static String stagedContent(HttpSession session) throws Exception {
        return Files.readString(new File(UploadAndPushKtrl.UPLOAD_PATH, staged(session).storedName()).toPath());
    }

    /**
     * gives sessionId an open terminal on a system with the given id
     */
    private static HostSystem openTerminal(long sessionId, long systemId) {
        HostSystem system = new HostSystem();
        system.setId(systemId);
        SchSession schSession = new SchSession();
        schSession.setHostSystem(system);
        schSession.setSession(mock(Session.class));
        UserSchSessions userSchSessions = new UserSchSessions();
        userSchSessions.getSchSessionMap().put(1, schSession);
        SecureShellKtrl.getUserSchSessionMap().put(sessionId, userSchSessions);
        return system;
    }

    private static void setField(UploadAndPushKtrl ktrl, String name, Object value) throws Exception {
        Field field = UploadAndPushKtrl.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(ktrl, value);
    }

    @Test
    void twoUsersUploadingTheSameFileNameDoNotOverwriteEachOther() throws Exception {
        HttpSession victim = signedInSession(1, 101);
        HttpSession attacker = signedInSession(7, 107);

        upload(victim, "authorized_keys", "VICTIM-CONTENT");
        upload(attacker, "authorized_keys", "ATTACKER-CONTENT");

        assertNotEquals(staged(victim).storedName(), staged(attacker).storedName());
        assertEquals("VICTIM-CONTENT", stagedContent(victim));
        assertEquals("ATTACKER-CONTENT", stagedContent(attacker));
        assertEquals("authorized_keys", staged(victim).fileName());
    }

    @Test
    void uploadedFileNameIsStrippedToABareFilename() throws Exception {
        HttpSession session = signedInSession(1, 101);
        upload(session, "../../../../etc/passwd", "x");

        assertEquals("passwd", staged(session).fileName());
        assertFalse(staged(session).storedName().contains("/"));
    }

    @Test
    void pushSendsOnlyThisSessionsUploadWhateverTheRequestNames() throws Exception {
        HttpSession victim = signedInSession(1, 101);
        upload(victim, "secret.txt", "VICTIM-PRIVATE-CANARY");
        File victimFile = new File(UploadAndPushKtrl.UPLOAD_PATH, staged(victim).storedName());

        HttpSession attacker = signedInSession(7, 107);
        upload(attacker, "mine.txt", "ATTACKER-CONTENT");
        File attackerFile = new File(UploadAndPushKtrl.UPLOAD_PATH, staged(attacker).storedName());
        HostSystem attackerSystem = openTerminal(107, 70);

        UploadAndPushKtrl ktrl = new UploadAndPushKtrl(requestFor(attacker), mock(HttpServletResponse.class));
        // even if something sets the field, push() takes the file from the session
        setField(ktrl, "uploadFileName", victimFile.getName());
        setField(ktrl, "pushDir", "~");

        List<String> sources = new ArrayList<>();
        List<String> destinations = new ArrayList<>();
        try (MockedStatic<SystemStatusDB> statusDB = mockStatic(SystemStatusDB.class);
             MockedStatic<SSHUtil> sshUtil = mockStatic(SSHUtil.class)) {
            statusDB.when(() -> SystemStatusDB.getNextPendingSystem(7L)).thenReturn(attackerSystem, (HostSystem) null);
            statusDB.when(() -> SystemStatusDB.getAllSystemStatus(7L)).thenReturn(Collections.emptyList());
            sshUtil.when(() -> SSHUtil.pushUpload(any(), any(), anyString(), anyString())).thenAnswer(i -> {
                sources.add(Files.readString(new File(i.<String>getArgument(2)).toPath()));
                destinations.add(i.getArgument(3));
                return i.getArgument(0);
            });

            ktrl.push();
        }

        assertEquals(List.of("ATTACKER-CONTENT"), sources);
        assertEquals(List.of("~/mine.txt"), destinations);
        // the attacker's finished push cleans up only the attacker's own upload
        assertFalse(attackerFile.exists());
        assertNull(staged(attacker));
        assertTrue(victimFile.exists());
        assertEquals("VICTIM-PRIVATE-CANARY", stagedContent(victim));
    }

    @Test
    void pushWithNothingUploadedPushesNothingAndDeletesNothing() throws Exception {
        HttpSession victim = signedInSession(1, 101);
        upload(victim, "secret.txt", "VICTIM-PRIVATE-CANARY");
        File victimFile = new File(UploadAndPushKtrl.UPLOAD_PATH, staged(victim).storedName());

        HttpSession attacker = signedInSession(7, 107);
        HostSystem attackerSystem = openTerminal(107, 70);
        UploadAndPushKtrl ktrl = new UploadAndPushKtrl(requestFor(attacker), mock(HttpServletResponse.class));
        setField(ktrl, "uploadFileName", victimFile.getName());

        try (MockedStatic<SystemStatusDB> statusDB = mockStatic(SystemStatusDB.class);
             MockedStatic<SSHUtil> sshUtil = mockStatic(SSHUtil.class)) {
            statusDB.when(() -> SystemStatusDB.getNextPendingSystem(7L)).thenReturn(attackerSystem);
            statusDB.when(() -> SystemStatusDB.getAllSystemStatus(7L)).thenReturn(Collections.emptyList());

            ktrl.push();

            sshUtil.verify(() -> SSHUtil.pushUpload(any(), any(), anyString(), anyString()), never());
        }

        assertTrue(victimFile.exists());
    }

    @Test
    void aNewUploadReplacesThisSessionsUnpushedOne() throws Exception {
        HttpSession session = signedInSession(1, 101);
        upload(session, "first.txt", "1");
        File first = new File(UploadAndPushKtrl.UPLOAD_PATH, staged(session).storedName());
        upload(session, "second.txt", "2");

        assertFalse(first.exists());
        assertEquals("second.txt", staged(session).fileName());
    }
}
