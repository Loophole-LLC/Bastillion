/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.db;

import io.bastillion.manage.model.Auth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * The database schema as a numbered list of migrations, with the version a database is at
 * recorded in schema_version.
 * <p>
 * Migrations 1-4 are the schema as it stood before versioning, every statement "if not
 * exists", so a database from any earlier release can run them all: whatever it already has
 * is skipped, and it ends up recorded at 4. From 5 on a migration runs exactly once per
 * database, so it does not need to be safe to repeat - add a new one to the end, never edit
 * one that has shipped.
 */
public final class SchemaMigrations {

    private static final Logger log = LoggerFactory.getLogger(SchemaMigrations.class);

    record Migration(int version, String description, List<String> statements) {
    }

    /**
     * Host certificate authorities Bastillion trusts - the fleet equivalent of a
     * {@code @cert-authority} line in known_hosts. A host presenting a certificate signed by
     * one of these needs no individual host key recorded or approved for it.
     */
    private static final String CREATE_HOST_CERT_AUTHORITY_TABLE =
            "create table if not exists host_cert_authority ("
                    + "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                    + "public_key varchar not null, "
                    + "fingerprint varchar not null unique, "
                    + "comment varchar, "
                    + "create_tm timestamp not null default CURRENT_TIMESTAMP())";

    /**
     * Bastillion's SSH certificate authority keypair - see
     * io.bastillion.manage.util.SshCertificateUtil. One row per authority type; next_serial
     * is the certificate serial counter sshd logs and a revocation list revokes against.
     */
    private static final String CREATE_CERT_AUTHORITY_TABLE =
            "create table if not exists cert_authority ("
                    + "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                    + "type varchar not null unique, "
                    + "public_key varchar not null, "
                    + "private_key varchar not null, "
                    + "create_tm timestamp not null default CURRENT_TIMESTAMP(), "
                    + "next_serial BIGINT not null default 0)";

    /**
     * Bastillion's known_hosts - see io.bastillion.manage.util.HostKeyVerifier. One row per
     * host, port and key type. The offered_* columns hold the key a host presented when it
     * did not match the trusted one, so the two can be compared instead of the new key
     * quietly replacing the approved one.
     */
    private static final String CREATE_HOST_KEY_TABLE =
            "create table if not exists host_key ("
                    + "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                    + "host varchar not null, "
                    + "port INTEGER not null, "
                    + "type varchar not null, "
                    + "public_key varchar not null, "
                    + "fingerprint varchar not null, "
                    + "status varchar not null default 'TRUSTED', "
                    + "offered_public_key varchar, "
                    + "offered_fingerprint varchar, "
                    + "first_seen_tm timestamp not null default CURRENT_TIMESTAMP(), "
                    + "approved_tm timestamp, "
                    + "approved_by INTEGER, "
                    + "foreign key (approved_by) references users(id) on delete set null, "
                    + "unique (host, port, type))";

    static final List<Migration> MIGRATIONS = List.of(
            new Migration(1, "base schema", List.of(
                    "create table if not exists users (id INTEGER PRIMARY KEY AUTO_INCREMENT, first_nm varchar, last_nm varchar, email varchar, username varchar not null unique, password varchar, auth_token varchar, auth_type varchar not null default '" + Auth.AUTH_BASIC + "', user_type varchar not null default '" + Auth.ADMINISTRATOR + "', salt varchar, otp_secret varchar, last_login_tm timestamp, expiration_tm timestamp)",
                    "create table if not exists user_theme (user_id INTEGER PRIMARY KEY, bg varchar(7), fg varchar(7), d1 varchar(7), d2 varchar(7), d3 varchar(7), d4 varchar(7), d5 varchar(7), d6 varchar(7), d7 varchar(7), d8 varchar(7), b1 varchar(7), b2 varchar(7), b3 varchar(7), b4 varchar(7), b5 varchar(7), b6 varchar(7), b7 varchar(7), b8 varchar(7), ui_theme varchar(5) not null default 'dark', foreign key (user_id) references users(id) on delete cascade) ",
                    "create table if not exists system (id INTEGER PRIMARY KEY AUTO_INCREMENT, display_nm varchar not null, username varchar not null, host varchar not null, port INTEGER not null, authorized_keys varchar not null, status_cd varchar not null default 'INITIAL')",
                    "create table if not exists profiles (id INTEGER PRIMARY KEY AUTO_INCREMENT, nm varchar not null, desc varchar not null)",
                    "create table if not exists system_map (profile_id INTEGER, system_id INTEGER, foreign key (profile_id) references profiles(id) on delete cascade , foreign key (system_id) references system(id) on delete cascade, primary key (profile_id, system_id))",
                    "create table if not exists user_map (user_id INTEGER, profile_id INTEGER, foreign key (user_id) references users(id) on delete cascade, foreign key (profile_id) references profiles(id) on delete cascade, primary key (user_id, profile_id))",
                    "create table if not exists application_key (id INTEGER PRIMARY KEY AUTO_INCREMENT, public_key varchar not null, private_key varchar not null, passphrase varchar)",
                    "create table if not exists status (id INTEGER, user_id INTEGER, status_cd varchar not null default 'INITIAL', foreign key (id) references system(id) on delete cascade, foreign key (user_id) references users(id) on delete cascade, primary key(id, user_id))",
                    "create table if not exists scripts (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, display_nm varchar not null, script varchar not null, foreign key (user_id) references users(id) on delete cascade)",
                    "create table if not exists public_keys (id INTEGER PRIMARY KEY AUTO_INCREMENT, key_nm varchar not null, type varchar, fingerprint varchar, public_key varchar, enabled boolean not null default true, create_dt timestamp not null default CURRENT_TIMESTAMP(), user_id INTEGER, profile_id INTEGER, foreign key (profile_id) references profiles(id) on delete cascade, foreign key (user_id) references users(id) on delete cascade)",
                    "create table if not exists session_log (id BIGINT PRIMARY KEY AUTO_INCREMENT, session_tm timestamp default CURRENT_TIMESTAMP, first_nm varchar, last_nm varchar, username varchar not null, ip_address varchar)",
                    "create table if not exists terminal_log (session_id BIGINT, instance_id INTEGER, output varchar not null, log_tm timestamp default CURRENT_TIMESTAMP, display_nm varchar not null, username varchar not null, host varchar not null, port INTEGER not null, foreign key (session_id) references session_log(id) on delete cascade)")),

            // installations from before the interface-theme preference
            new Migration(2, "user_theme.ui_theme", List.of(
                    "alter table user_theme add column if not exists ui_theme varchar(5) not null default 'dark'")),

            // Existing installations have no recorded host keys, which is why
            // hostKeyVerification defaults to accept-new rather than strict - an upgrade
            // records each host's key on its next connection instead of refusing every
            // connection until a manager has approved every host.
            new Migration(3, "host keys and certificate authorities (6.0.0)", List.of(
                    CREATE_HOST_KEY_TABLE,
                    CREATE_CERT_AUTHORITY_TABLE,
                    CREATE_HOST_CERT_AUTHORITY_TABLE)),

            // How the last connection to each system authenticated, so a certificate rollout
            // can be seen on the systems screen rather than only in the audit log. Null on
            // every existing row until that system is next connected to.
            new Migration(4, "system.last_auth_method (6.0.0)", List.of(
                    "alter table system add column if not exists last_auth_method varchar"))
    );

    private SchemaMigrations() {
    }

    /**
     * @param con DB connection
     * @return the version recorded in schema_version, or 0 for a database that predates it
     */
    static int currentVersion(Connection con) throws SQLException {
        try (Statement stmt = con.createStatement()) {
            stmt.executeUpdate("create table if not exists schema_version (version INTEGER PRIMARY KEY, description varchar not null, applied_tm timestamp not null default CURRENT_TIMESTAMP())");
            try (ResultSet rs = stmt.executeQuery("select coalesce(max(version), 0) from schema_version")) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    /**
     * Applies every migration newer than the database's recorded version, recording each.
     *
     * @param con DB connection
     * @return the version the database is at afterwards
     */
    public static int migrate(Connection con) throws SQLException {
        return migrate(con, MIGRATIONS);
    }

    static int migrate(Connection con, List<Migration> migrations) throws SQLException {
        int version = currentVersion(con);
        int latest = migrations.get(migrations.size() - 1).version();
        if (version > latest) {
            // a database written by a newer release - carry on rather than refuse to start,
            // but say so, since this release does not know what those migrations changed
            log.warn("Database schema is at version " + version + " but this release only knows up to " + latest);
            return version;
        }

        for (Migration migration : migrations) {
            if (migration.version() <= version) {
                continue;
            }
            try (Statement stmt = con.createStatement()) {
                for (String sql : migration.statements()) {
                    stmt.executeUpdate(sql);
                }
            }
            try (PreparedStatement stmt = con.prepareStatement("insert into schema_version (version, description) values (?, ?)")) {
                stmt.setInt(1, migration.version());
                stmt.setString(2, migration.description());
                stmt.execute();
            }
            System.out.println("Applied database migration " + migration.version() + ": " + migration.description());
            version = migration.version();
        }
        return version;
    }
}
