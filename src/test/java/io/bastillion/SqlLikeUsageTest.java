/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A SQL LIKE treats % and _ in its value as wildcards, so a lookup that means "this exact
 * username / token / role" matches other rows as well - that is how GHSA-5qgc-52c7-26mg let
 * john_smith@corp.com sign in as john.smith@corp.com, and how an LDAP role web_prod landed in
 * the web-prod profile. Exact lookups use =; a line that really is a search says so with
 * {@value #MARKER} and gets past this check.
 */
class SqlLikeUsageTest {

    private static final String MARKER = "intentional LIKE";
    private static final Pattern LIKE = Pattern.compile("(?i)\\blike\\s*(\\?|'|lower\\(|upper\\()");

    @Test
    void everyLikeInMainSourcesIsMarkedIntentional() throws IOException {
        List<String> unmarked = new ArrayList<>();
        try (Stream<Path> files = Files.walk(Paths.get("src/main/java"))) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (LIKE.matcher(line).find() && !line.contains(MARKER)) {
                        unmarked.add(file + ":" + (i + 1) + ": " + line.trim());
                    }
                }
            }
        }
        assertEquals(List.of(), unmarked, "Use = for exact lookups, or mark a real search with \"// " + MARKER + "\"");
    }

    @Test
    void patternCatchesTheFormsThatCausedBugs() {
        assertTrue(LIKE.matcher("select * from users where lower(username) like lower(?)").find());
        assertTrue(LIKE.matcher("select id from profiles p where lower(p.nm) like ?").find());
        assertTrue(LIKE.matcher("where u.user_type like 'A'").find());
    }
}
