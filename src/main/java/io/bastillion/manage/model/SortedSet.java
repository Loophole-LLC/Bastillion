/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * allows for paged results on the display screens
 */
public class SortedSet {
    private String orderByField = null;
    private String orderByDirection = "asc";
    private List itemList;
    private Map<String, String> filterMap = new HashMap<>();

    public SortedSet() {

    }

    public SortedSet(String orderByField) {
        this.orderByField = orderByField;
    }


    /**
     * Characters allowed to survive in a sort field for display and for round-tripping back
     * into the page's own sort links.
     * <p>
     * The expression this replaced, {@code [^0-9,a-z,A-Z,\_,\.]}, was written as though a
     * character class took comma-separated ranges. The commas in it were literal, so a comma
     * was one of the characters it preserved rather than stripped - and the result was
     * concatenated straight into an {@code order by} clause. Whether a field reaches SQL at
     * all is now decided by {@link #toOrderByClause(Set)}'s allowlist, but a comma was never
     * meant to be part of a column name here either.
     */
    private static final Pattern DISALLOWED_IN_SORT_FIELD = Pattern.compile("[^0-9a-zA-Z_.]");

    public String getOrderByField() {

        if (orderByField != null) {
            return DISALLOWED_IN_SORT_FIELD.matcher(orderByField).replaceAll("");
        }
        return null;

    }

    public void setOrderByField(String orderByField) {
        this.orderByField = orderByField;
    }


    public String getOrderByDirection() {
        if ("asc".equalsIgnoreCase(orderByDirection)) {
            return "asc";
        } else {
            return "desc";
        }
    }

    public void setOrderByDirection(String orderByDirection) {
        this.orderByDirection = orderByDirection;
    }

    /**
     * @param sortableFields the columns the calling query actually permits sorting on
     * @return " order by &lt;field&gt; &lt;direction&gt;" if the requested sort field is one of
     * {@code sortableFields}, otherwise "" - the query runs unordered rather than failing
     * <p>
     * The clause is string-concatenated into SQL by every caller, because a column name
     * cannot be a bound parameter. It is therefore an allowlist of known column names and
     * not a character filter: stripping punctuation out of the field still left the caller
     * ordering by whatever column the client named, and a column does not have to be
     * displayed to be sortable. Ordering the user list by {@code password} or a key list by
     * {@code private_key} leaks the relative order of those values across pages - no
     * quoting, keyword or metacharacter needed. {@link #getOrderByDirection()} is already
     * constrained to exactly "asc" or "desc".
     */
    public String toOrderByClause(Set<String> sortableFields) {
        String field = getOrderByField();
        if (field == null || field.trim().isEmpty() || !sortableFields.contains(field)) {
            return "";
        }
        return " order by " + field + " " + getOrderByDirection();
    }

    /**
     * The current sort state as query parameters, for carrying it across a redirect back to
     * a list view: {@code return "redirect:/manage/viewUsers.ktrl?" + sortedSet.toQueryString()}.
     * <p>
     * Eleven controller methods each built this same string by hand. No URL encoding is
     * needed (or applied): the direction is always exactly "asc" or "desc", and
     * {@link #getOrderByField()} has already reduced the field to word characters and dots.
     *
     * @return "sortedSet.orderByDirection=...", plus "&amp;sortedSet.orderByField=..." when a
     * sort field is set
     */
    public String toQueryString() {
        String query = "sortedSet.orderByDirection=" + getOrderByDirection();
        String field = getOrderByField();
        if (field != null && !field.trim().isEmpty()) {
            query = query + "&sortedSet.orderByField=" + field;
        }
        return query;
    }

    public List getItemList() {
        return itemList;
    }

    public void setItemList(List itemList) {

        this.itemList = itemList;
    }

    public Map<String, String> getFilterMap() {
        return filterMap;
    }

    public void setFilterMap(Map<String, String> filterMap) {
        this.filterMap = filterMap;
    }
}
