/**
 * Copyright (C) 2018 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package loophole.mvc.base;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Holds Bastillion's own controllers to the {@code @Model(params = ...)} allowlist.
 * <p>
 * The test JVM only scans the framework's test controllers, so the startup checks in
 * {@link BaseKontroller#acceptedParams} are run here over the application's controllers
 * too. And since a form field missing from the allowlist is not an error - it is simply
 * ignored, which is the point - every parameter name the templates send is checked against
 * what some controller accepts, so adding a form field without declaring it fails the build
 * instead of quietly doing nothing.
 */
class ApplicationControllerParamsTest {

    private static final Path CONTROLLERS = Path.of("target/classes/io/bastillion/manage/control");
    private static final Path WEBAPP = Path.of("src/main/webapp");

    /**
     * Sent by the templates but deliberately not bound: read directly by a controller or a
     * filter, used only by the page's own script, or set by the controller itself.
     */
    private static final Set<String> NOT_BOUND = Set.of(
            "_csrf",            // SecurityFilter
            "upload",           // multipart, parsed by UploadAndPushKtrl itself
            "connectHostId",    // secure_shell.html script, sent on as systemSelectId
            "systemSelectAll",  // view_systems.html select-all checkbox
            "filter",           // view_terms.html client-side output filter
            "t"                 // cache buster on term output polling
    );

    private static final Pattern NAME_ATTRIBUTE = Pattern.compile("\\bname=\"([A-Za-z_][^\"]*)\"");
    private static final Pattern QUERY_KEY = Pattern.compile("[?&]([A-Za-z_][A-Za-z_.]*)=");
    private static final Pattern QUOTED_DATA_KEY = Pattern.compile("'([a-z][A-Za-z]*(?:\\.[a-z][A-Za-z]*)+)'\\s*:");
    private static final Pattern FILTER_MAP_KEY = Pattern.compile("'(sortedSet\\.filterMap)\\[");

    private static List<Class<?>> applicationControllers() throws Exception {
        List<Class<?>> controllers = new ArrayList<>();
        try (Stream<Path> files = Files.list(CONTROLLERS)) {
            for (Path file : files.filter(f -> f.toString().endsWith("Ktrl.class")).sorted().toList()) {
                String name = file.getFileName().toString().replace(".class", "");
                Class<?> clazz = Class.forName("io.bastillion.manage.control." + name);
                if (BaseKontroller.class.equals(clazz.getSuperclass())) {
                    controllers.add(clazz);
                }
            }
        }
        return controllers;
    }

    @Test
    void everyControllersDeclaredParamsPassTheStartupChecks() throws Exception {
        List<Class<?>> controllers = applicationControllers();
        assertFalse(controllers.isEmpty(), "no controllers found under " + CONTROLLERS);
        for (Class<?> controller : controllers) {
            BaseKontroller.acceptedParams(controller);
        }
    }

    @Test
    void everyParameterTheTemplatesSendIsAcceptedBySomeController() throws Exception {
        Set<String> accepted = new HashSet<>();
        for (Class<?> controller : applicationControllers()) {
            accepted.addAll(BaseKontroller.acceptedParams(controller));
        }

        Set<String> unaccepted = new TreeSet<>();
        for (Path template : templates()) {
            for (String param : parametersSentBy(template)) {
                if (!accepted.contains(param) && !NOT_BOUND.contains(param)) {
                    unaccepted.add(param + "  (" + WEBAPP.relativize(template) + ")");
                }
            }
        }
        assertEquals(Set.of(), unaccepted, "sent by a template but accepted by no controller's @Model(params)");
    }

    private static List<Path> templates() throws IOException {
        try (Stream<Path> files = Files.walk(WEBAPP)) {
            return files.filter(f -> f.toString().endsWith(".html") || f.toString().endsWith(".js"))
                    .filter(f -> !f.startsWith(WEBAPP.resolve("_res/node")))
                    .toList();
        }
    }

    private static Set<String> parametersSentBy(Path template) throws IOException {
        String content = Files.readString(template);
        Set<String> params = new HashSet<>();
        for (Pattern pattern : List.of(NAME_ATTRIBUTE, QUERY_KEY, QUOTED_DATA_KEY, FILTER_MAP_KEY)) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                params.add(BaseKontroller.withoutMapKeys(matcher.group(1)));
            }
        }
        // meta tags, not form fields
        params.remove("viewport");
        params.remove("theme-color");
        return params;
    }
}
