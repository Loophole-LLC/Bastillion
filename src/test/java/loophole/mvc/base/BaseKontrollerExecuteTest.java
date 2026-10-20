/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.base;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletException;
import loophole.mvc.testctrl.DummyController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.Map;

import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link BaseKontroller#execute()} end to end against {@link DummyController},
 * which is scanned via the {@code MVC_CONTROLLER_PKGS} system property configured for
 * the surefire plugin in pom.xml.
 */
@ExtendWith(MockitoExtension.class)
class BaseKontrollerExecuteTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @BeforeEach
    void setUp() {
        DummyController.reset();
    }

    @Test
    void invokesControllerMethodMatchingPathAndHttpMethod() throws Exception {
        when(request.getServletPath()).thenReturn("/hello.ktrl");
        when(request.getMethod()).thenReturn("GET");
        when(request.getParameterNames()).thenReturn(Collections.emptyEnumeration());

        String forward = new BaseKontroller(request, response).execute();

        assertTrue(DummyController.helloExecuted);
        assertEquals("forward:/hello.html", forward);
    }

    @Test
    void doesNotInvokeControllerMethodWhenHttpMethodDoesNotMatch() throws Exception {
        when(request.getServletPath()).thenReturn("/hello.ktrl");
        when(request.getMethod()).thenReturn("POST");

        String forward = new BaseKontroller(request, response).execute();

        assertFalse(DummyController.helloExecuted);
        assertEquals(null, forward);
    }

    @Test
    void populatesModelAnnotatedFieldsFromRequestParametersAndBack() throws Exception {
        when(request.getServletPath()).thenReturn("/echo.ktrl");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterNames()).thenReturn(Collections.enumeration(java.util.List.of("name", "age")));
        when(request.getParameter("name")).thenReturn("world");
        when(request.getParameter("age")).thenReturn("42");

        String forward = new BaseKontroller(request, response).execute();

        assertTrue(DummyController.echoExecuted);
        assertEquals("forward:/echo.html", forward);
        verify(request).setAttribute("greeting", "hello world (42)");
    }

    @Test
    void doesNotBindRequestParameterIntoOutputOnlyModel() throws Exception {
        when(request.getServletPath()).thenReturn("/serverValue.ktrl");
        when(request.getMethod()).thenReturn("POST");
        // no getParameter stub: the binder must not even read a parameter naming the field
        when(request.getParameterNames()).thenReturn(Collections.enumeration(java.util.List.of("serverValue")));

        new BaseKontroller(request, response).execute();

        verify(request).setAttribute("serverValue", "set by the controller");
    }

    // --- setFieldFromParams' bracketed-key parsing (tags[env]=prod -> Map.put("env", "prod")) ---
    // Regression coverage for the java/polynomial-redos fix: the key extraction used to
    // chain three replaceAll regexes (".*\\[", "\\'", "\\]. *") over the attacker-controlled
    // parameter name, which could backtrack quadratically on crafted input. It was replaced
    // with plain lastIndexOf/substring/literal-replace, which must preserve the exact same
    // key extracted in each of these cases.

    @Test
    void populatesMapModelFieldFromBracketedParameterName() throws Exception {
        when(request.getServletPath()).thenReturn("/tags.ktrl");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterNames()).thenReturn(Collections.enumeration(java.util.List.of("tags[env]")));
        when(request.getParameter("tags[env]")).thenReturn("prod");

        new BaseKontroller(request, response).execute();

        assertTrue(DummyController.tagsExecuted);
        ArgumentCaptor<Map> tagsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(request).setAttribute(eq("tags"), tagsCaptor.capture());
        assertEquals("prod", tagsCaptor.getValue().get("env"));
    }

    @Test
    void stripsQuotesFromBracketedParameterKey() throws Exception {
        when(request.getServletPath()).thenReturn("/tags.ktrl");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterNames()).thenReturn(Collections.enumeration(java.util.List.of("tags['env']")));
        when(request.getParameter("tags['env']")).thenReturn("prod");

        new BaseKontroller(request, response).execute();

        ArgumentCaptor<Map> tagsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(request).setAttribute(eq("tags"), tagsCaptor.capture());
        assertEquals("prod", tagsCaptor.getValue().get("env"));
    }

    @Test
    void handlesBracketedParameterKeyMissingClosingBracket() throws Exception {
        when(request.getServletPath()).thenReturn("/tags.ktrl");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterNames()).thenReturn(Collections.enumeration(java.util.List.of("tags[env")));
        when(request.getParameter("tags[env")).thenReturn("prod");

        new BaseKontroller(request, response).execute();

        ArgumentCaptor<Map> tagsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(request).setAttribute(eq("tags"), tagsCaptor.capture());
        assertEquals("prod", tagsCaptor.getValue().get("env"));
    }

    @Test
    void handlesAdversarialBracketedParameterNameWithoutQuadraticSlowdown() throws Exception {
        // Shape that caused catastrophic backtracking under the old ".*\\[" regex: an
        // opening bracket followed by a long run of a repeated character and no closing
        // bracket, so every suffix after the last successful match previously failed to
        // match only after an O(n) backtrack - O(n^2) overall for n this large.
        String hugeUnclosedKey = "tags[" + "a".repeat(200_000);
        when(request.getServletPath()).thenReturn("/tags.ktrl");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterNames()).thenReturn(Collections.enumeration(java.util.List.of(hugeUnclosedKey)));
        when(request.getParameter(hugeUnclosedKey)).thenReturn("prod");

        assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () ->
                new BaseKontroller(request, response).execute());
    }

    @Test
    void skipsExecuteMethodAndReturnsValidationInputWhenValidateAddsFieldError() throws Exception {
        when(request.getServletPath()).thenReturn("/validate.ktrl");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameterNames()).thenReturn(Collections.emptyEnumeration());

        String forward = new BaseKontroller(request, response).execute();

        assertTrue(DummyController.validateSubmitExecuted);
        assertFalse(DummyController.submitExecuted);
        assertEquals("forward:/error.html", forward);

        ArgumentCaptor<Map> fieldErrorsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(request).setAttribute(eq("fieldErrors"), fieldErrorsCaptor.capture());
        assertEquals("name is required", fieldErrorsCaptor.getValue().get("name"));
    }

    @Test
    void controllerExceptionsDoNotExposeInternalDetailsToTheContainer() {
        when(request.getServletPath()).thenReturn("/throws.ktrl");
        when(request.getMethod()).thenReturn("GET");
        when(request.getParameterNames()).thenReturn(Collections.emptyEnumeration());

        ServletException exception = assertThrows(ServletException.class,
                () -> new BaseKontroller(request, response).execute());

        assertEquals("Request processing failed", exception.getMessage());
        assertNull(exception.getCause());
    }
}
