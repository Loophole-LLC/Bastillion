/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.db;

import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every startup runs migrate() against whatever database is there - empty, from any earlier
 * release, or already current - so each of those has to end up at the latest version with
 * its data intact, and a migration past the baseline must run exactly once.
 */
class SchemaMigrationsTest {

    private static final int LATEST = SchemaMigrations.MIGRATIONS.get(SchemaMigrations.MIGRATIONS.size() - 1).version();

    private Connection newDatabase() throws SQLException {
        return DriverManager.getConnection("jdbc:h2:mem:schema_test_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
    }

    private boolean columnExists(Connection con, String table, String column) throws SQLException {
        try (ResultSet rs = con.getMetaData().getColumns(null, "PUBLIC", table.toUpperCase(), column.toUpperCase())) {
            return rs.next();
        }
    }

    private boolean tableExists(Connection con, String table) throws SQLException {
        try (ResultSet rs = con.getMetaData().getTables(null, "PUBLIC", table.toUpperCase(), null)) {
            return rs.next();
        }
    }

    private int count(Connection con, String sql) throws SQLException {
        try (Statement stmt = con.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            rs.next();
            return rs.getInt(1);
        }
    }

    @Test
    void emptyDatabaseGetsTheWholeSchema() throws SQLException {
        try (Connection con = newDatabase()) {
            assertEquals(LATEST, SchemaMigrations.migrate(con));

            for (String table : List.of("users", "user_theme", "system", "profiles", "public_keys", "session_log",
                    "terminal_log", "host_key", "cert_authority", "host_cert_authority")) {
                assertTrue(tableExists(con, table), table);
            }
            assertTrue(columnExists(con, "system", "last_auth_method"));
            assertEquals(LATEST, count(con, "select count(*) from schema_version"));
        }
    }

    @Test
    void secondStartupChangesNothing() throws SQLException {
        try (Connection con = newDatabase()) {
            SchemaMigrations.migrate(con);

            assertEquals(LATEST, SchemaMigrations.migrate(con));
            assertEquals(LATEST, count(con, "select count(*) from schema_version"));
        }
    }

    @Test
    void preVersioningDatabaseIsUpgradedWithDataIntact() throws SQLException {
        try (Connection con = newDatabase(); Statement stmt = con.createStatement()) {
            // a 5.2.x database: base tables, user_theme without ui_theme, nothing from 6.0.0
            for (String sql : SchemaMigrations.MIGRATIONS.get(0).statements()) {
                stmt.executeUpdate(sql);
            }
            stmt.executeUpdate("alter table user_theme drop column ui_theme");
            stmt.executeUpdate("insert into users (username) values ('admin')");
            stmt.executeUpdate("insert into system (display_nm, username, host, port, authorized_keys) values ('web', 'root', 'web1', 22, '~/.ssh/authorized_keys')");

            assertEquals(LATEST, SchemaMigrations.migrate(con));

            assertTrue(columnExists(con, "user_theme", "ui_theme"));
            assertTrue(columnExists(con, "system", "last_auth_method"));
            assertTrue(tableExists(con, "host_key"));
            assertEquals(1, count(con, "select count(*) from users where username='admin'"));
            assertEquals(1, count(con, "select count(*) from system where host='web1'"));
        }
    }

    @Test
    void currentButUnversionedDatabaseIsJustStamped() throws SQLException {
        try (Connection con = newDatabase(); Statement stmt = con.createStatement()) {
            // a 6.0.x database: everything present, no schema_version yet
            for (SchemaMigrations.Migration migration : SchemaMigrations.MIGRATIONS) {
                for (String sql : migration.statements()) {
                    stmt.executeUpdate(sql);
                }
            }

            assertEquals(LATEST, SchemaMigrations.migrate(con));
        }
    }

    @Test
    void laterMigrationRunsExactlyOnce() throws SQLException {
        List<SchemaMigrations.Migration> migrations = new ArrayList<>(SchemaMigrations.MIGRATIONS);
        // deliberately not repeatable - fails if it runs a second time
        migrations.add(new SchemaMigrations.Migration(LATEST + 1, "test column",
                List.of("alter table system add column test_col varchar")));

        try (Connection con = newDatabase()) {
            assertEquals(LATEST + 1, SchemaMigrations.migrate(con, migrations));
            assertEquals(LATEST + 1, SchemaMigrations.migrate(con, migrations));
            assertTrue(columnExists(con, "system", "test_col"));
        }
    }

    @Test
    void databaseFromANewerReleaseIsLeftAlone() throws SQLException {
        try (Connection con = newDatabase()) {
            SchemaMigrations.migrate(con);
            try (Statement stmt = con.createStatement()) {
                stmt.executeUpdate("insert into schema_version (version, description) values (" + (LATEST + 10) + ", 'future')");
            }

            assertEquals(LATEST + 10, SchemaMigrations.migrate(con));
        }
    }
}
