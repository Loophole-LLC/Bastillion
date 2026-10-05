/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.model;

import io.bastillion.manage.db.UserDB;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The order-by clause is concatenated into SQL by every DAO that pages a list, because a
 * column name cannot be a bound parameter - so what reaches SQL is decided here.
 */
class SortedSetTest {

    private static final Set<String> SORTABLE = Set.of("username", "last_nm");

    @Test
    void buildsAnOrderByClauseForAPermittedColumn() {
        SortedSet sortedSet = new SortedSet("username");
        sortedSet.setOrderByDirection("desc");

        assertEquals(" order by username desc", sortedSet.toOrderByClause(SORTABLE));
    }

    @Test
    void omitsTheClauseEntirelyForAColumnTheQueryDoesNotOffer() {
        // The field survives character filtering - it is a perfectly well-formed column name,
        // just not one this list is allowed to be ordered by. Sorting the user list by its
        // password column leaks the relative order of every stored hash across pages, with no
        // quoting or metacharacter involved.
        SortedSet sortedSet = new SortedSet(UserDB.PASSWORD);

        assertEquals("", sortedSet.toOrderByClause(SORTABLE));
    }

    @Test
    void omitsTheClauseWhenNoSortFieldIsSet() {
        assertEquals("", new SortedSet().toOrderByClause(SORTABLE));
    }

    @Test
    void stripsCommasFromTheSortFieldRatherThanPreservingThem() {
        // The previous filter was [^0-9,a-z,A-Z,\_,\.], written as though a character class
        // took comma-separated ranges; its commas were literal, so a comma was one of the
        // characters it kept.
        SortedSet sortedSet = new SortedSet("username,password");

        assertEquals("usernamepassword", sortedSet.getOrderByField());
    }

    @Test
    void acceptsOnlyAscOrDescAsADirection() {
        SortedSet sortedSet = new SortedSet("username");
        sortedSet.setOrderByDirection("asc; drop table users");

        assertEquals("desc", sortedSet.getOrderByDirection());
        assertEquals(" order by username desc", sortedSet.toOrderByClause(SORTABLE));
    }

    // --- toQueryString: carries the sort across a redirect back to a list view ---

    @Test
    void buildsTheSortQueryStringWithBothParameters() {
        SortedSet sortedSet = new SortedSet("last_nm");
        sortedSet.setOrderByDirection("desc");

        assertEquals("sortedSet.orderByDirection=desc&sortedSet.orderByField=last_nm",
                sortedSet.toQueryString());
    }

    @Test
    void leavesTheSortFieldOutOfTheQueryStringWhenUnset() {
        assertEquals("sortedSet.orderByDirection=asc", new SortedSet().toQueryString());
    }
}
