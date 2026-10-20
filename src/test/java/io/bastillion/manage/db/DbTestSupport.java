/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

/**
 * Spins up a fresh, isolated H2 in-memory database per call - deliberately bypassing
 * DSPool/AppConfig (which cache a single DataSource for the whole test JVM) so DAO tests
 * don't fight over shared connection state. Only the subset of DBInitServlet's schema
 * needed by the DAO methods under test is created.
 */
public final class DbTestSupport {

    private DbTestSupport() {
    }

    public static Connection newConnection() throws SQLException {
        // Unique DB name per call so parallel/successive tests never see each other's rows.
        Connection con = DriverManager.getConnection(
                "jdbc:h2:mem:bastillion_test_" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        try (Statement stmt = con.createStatement()) {
            stmt.executeUpdate("create table users (id INTEGER PRIMARY KEY AUTO_INCREMENT, first_nm varchar, last_nm varchar, email varchar, username varchar not null unique, user_type varchar not null default 'A', last_login_tm timestamp, expiration_tm timestamp)");
            stmt.executeUpdate("create table system (id INTEGER PRIMARY KEY AUTO_INCREMENT, display_nm varchar not null, username varchar not null, host varchar not null, port INTEGER not null, authorized_keys varchar not null, status_cd varchar not null default 'INITIAL')");
            stmt.executeUpdate("create table profiles (id INTEGER PRIMARY KEY AUTO_INCREMENT, nm varchar not null, desc varchar not null)");
            stmt.executeUpdate("create table system_map (profile_id INTEGER, system_id INTEGER, foreign key (profile_id) references profiles(id) on delete cascade, foreign key (system_id) references system(id) on delete cascade, primary key (profile_id, system_id))");
            stmt.executeUpdate("create table user_map (user_id INTEGER, profile_id INTEGER, foreign key (user_id) references users(id) on delete cascade, foreign key (profile_id) references profiles(id) on delete cascade, primary key (user_id, profile_id))");
            stmt.executeUpdate("create table public_keys (id INTEGER PRIMARY KEY AUTO_INCREMENT, key_nm varchar not null, type varchar, fingerprint varchar, public_key varchar, enabled boolean not null default true, create_dt timestamp not null default CURRENT_TIMESTAMP(), user_id INTEGER, profile_id INTEGER, foreign key (profile_id) references profiles(id) on delete cascade, foreign key (user_id) references users(id) on delete cascade)");
            stmt.executeUpdate("create table session_log (id BIGINT PRIMARY KEY AUTO_INCREMENT, session_tm timestamp default CURRENT_TIMESTAMP, first_nm varchar, last_nm varchar, username varchar not null, ip_address varchar)");
            stmt.executeUpdate("create table terminal_log (session_id BIGINT, instance_id INTEGER, output varchar not null, log_tm timestamp default CURRENT_TIMESTAMP, display_nm varchar not null, username varchar not null, host varchar not null, port INTEGER not null, foreign key (session_id) references session_log(id) on delete cascade)");
        }
        return con;
    }
}
