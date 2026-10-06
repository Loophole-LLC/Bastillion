/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.common.db;

import com.jcraft.jsch.JSchException;
import io.bastillion.common.util.AppConfig;
import io.bastillion.manage.db.CertAuthorityDB;
import io.bastillion.manage.db.PrivateKeyDB;
import io.bastillion.manage.model.ApplicationKey;
import io.bastillion.manage.model.Auth;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.util.DBUtils;
import io.bastillion.manage.util.EncryptionUtil;
import io.bastillion.manage.util.RefreshAuthKeyUtil;
import io.bastillion.manage.util.KeyManagement;
import io.bastillion.manage.util.SSHUtil;
import io.bastillion.manage.util.SshCertificateAuth;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

/**
 * Initial startup task.  Creates an H2 DB and generates
 * the system public/private key pair if none exists
 */
@WebServlet(name = "DBInitServlet",
        urlPatterns = {"/config"},
        loadOnStartup = 1)
public class DBInitServlet extends jakarta.servlet.http.HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(DBInitServlet.class);

    /**
     * Bastillion's known_hosts - see io.bastillion.manage.util.HostKeyVerifier. One row per
     * host, port and key type. The offered_* columns hold the key a host presented when it
     * did not match the trusted one, so the two can be compared instead of the new key
     * quietly replacing the approved one.
     */
    /**
     * Bastillion's SSH certificate authority keypair - see
     * io.bastillion.manage.util.SshCertificateUtil. One row per authority type; next_serial
     * is the certificate serial counter sshd logs and a revocation list revokes against.
     */
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

    private static final String CREATE_CERT_AUTHORITY_TABLE =
            "create table if not exists cert_authority ("
                    + "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                    + "type varchar not null unique, "
                    + "public_key varchar not null, "
                    + "private_key varchar not null, "
                    + "create_tm timestamp not null default CURRENT_TIMESTAMP(), "
                    + "next_serial BIGINT not null default 0)";

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

    /**
     * task init method that created DB and generated public/private keys
     *
     * @param config task config
     */
    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        Connection connection = null;
        Statement statement = null;
        //check if reset ssh application key is set
        boolean resetSSHKey = "true".equals(AppConfig.getProperty("resetApplicationSSHKey"));

        try {
            //if DB password is empty generate a random
            if (StringUtils.isEmpty(AppConfig.getProperty("dbPassword"))) {
                String dbPassword = null;
                String dbPasswordConfirm = null;
                if (!"true".equals(System.getProperty("GEN_DB_PASS"))) {
                    //prompt for password and confirmation
                    while (dbPassword == null || !dbPassword.equals(dbPasswordConfirm)) {
                        if (System.console() == null) {
                            Scanner in = new Scanner(System.in);
                            System.out.println("Please enter database password: ");
                            dbPassword = in.nextLine();
                            System.out.println("Please confirm database password: ");
                            dbPasswordConfirm = in.nextLine();
                        } else {
                            dbPassword = new String(System.console().readPassword("Please enter database password: "));
                            dbPasswordConfirm = new String(System.console().readPassword("Please confirm database password: "));
                        }
                        if (!dbPassword.equals(dbPasswordConfirm)) {
                            System.out.println("Passwords do not match");
                        }
                    }
                }
                //set password
                if (StringUtils.isNotEmpty(dbPassword)) {
                    AppConfig.encryptProperty("dbPassword", dbPassword);
                    //if password not set generate a random
                } else {
                    System.out.println("Generating random database password");
                    AppConfig.encryptProperty("dbPassword", RandomStringUtils.random(32, true, true));
                }
                //else encrypt password if plain-text
            } else if (!AppConfig.isPropertyEncrypted("dbPassword")) {
                AppConfig.encryptProperty("dbPassword", AppConfig.getProperty("dbPassword"));
            }

            connection = DBUtils.getConn();
            statement = connection.createStatement();

            ResultSet rs = statement.executeQuery("select * from information_schema.tables where upper(table_name) = 'USERS' and table_schema='PUBLIC'");
            if (!rs.next()) {
                resetSSHKey = true;

                //create DB objects
                statement.executeUpdate("create table if not exists users (id INTEGER PRIMARY KEY AUTO_INCREMENT, first_nm varchar, last_nm varchar, email varchar, username varchar not null unique, password varchar, auth_token varchar, auth_type varchar not null default '" + Auth.AUTH_BASIC + "', user_type varchar not null default '" + Auth.ADMINISTRATOR + "', salt varchar, otp_secret varchar, last_login_tm timestamp, expiration_tm timestamp)");
                statement.executeUpdate("create table if not exists user_theme (user_id INTEGER PRIMARY KEY, bg varchar(7), fg varchar(7), d1 varchar(7), d2 varchar(7), d3 varchar(7), d4 varchar(7), d5 varchar(7), d6 varchar(7), d7 varchar(7), d8 varchar(7), b1 varchar(7), b2 varchar(7), b3 varchar(7), b4 varchar(7), b5 varchar(7), b6 varchar(7), b7 varchar(7), b8 varchar(7), ui_theme varchar(5) not null default 'dark', foreign key (user_id) references users(id) on delete cascade) ");
                statement.executeUpdate("create table if not exists system (id INTEGER PRIMARY KEY AUTO_INCREMENT, display_nm varchar not null, username varchar not null, host varchar not null, port INTEGER not null, authorized_keys varchar not null, status_cd varchar not null default 'INITIAL')");
                statement.executeUpdate("create table if not exists profiles (id INTEGER PRIMARY KEY AUTO_INCREMENT, nm varchar not null, desc varchar not null)");
                statement.executeUpdate("create table if not exists system_map (profile_id INTEGER, system_id INTEGER, foreign key (profile_id) references profiles(id) on delete cascade , foreign key (system_id) references system(id) on delete cascade, primary key (profile_id, system_id))");
                statement.executeUpdate("create table if not exists user_map (user_id INTEGER, profile_id INTEGER, foreign key (user_id) references users(id) on delete cascade, foreign key (profile_id) references profiles(id) on delete cascade, primary key (user_id, profile_id))");
                statement.executeUpdate("create table if not exists application_key (id INTEGER PRIMARY KEY AUTO_INCREMENT, public_key varchar not null, private_key varchar not null, passphrase varchar)");

                statement.executeUpdate("create table if not exists status (id INTEGER, user_id INTEGER, status_cd varchar not null default 'INITIAL', foreign key (id) references system(id) on delete cascade, foreign key (user_id) references users(id) on delete cascade, primary key(id, user_id))");
                statement.executeUpdate("create table if not exists scripts (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, display_nm varchar not null, script varchar not null, foreign key (user_id) references users(id) on delete cascade)");


                statement.executeUpdate("create table if not exists public_keys (id INTEGER PRIMARY KEY AUTO_INCREMENT, key_nm varchar not null, type varchar, fingerprint varchar, public_key varchar, enabled boolean not null default true, create_dt timestamp not null default CURRENT_TIMESTAMP(), user_id INTEGER, profile_id INTEGER, foreign key (profile_id) references profiles(id) on delete cascade, foreign key (user_id) references users(id) on delete cascade)");

                statement.executeUpdate("create table if not exists session_log (id BIGINT PRIMARY KEY AUTO_INCREMENT, session_tm timestamp default CURRENT_TIMESTAMP, first_nm varchar, last_nm varchar, username varchar not null, ip_address varchar)");
                statement.executeUpdate("create table if not exists terminal_log (session_id BIGINT, instance_id INTEGER, output varchar not null, log_tm timestamp default CURRENT_TIMESTAMP, display_nm varchar not null, username varchar not null, host varchar not null, port INTEGER not null, foreign key (session_id) references session_log(id) on delete cascade)");

                //if exists readfile to set default password
                String salt = EncryptionUtil.generateSalt();
                String defaultPassword = EncryptionUtil.hashV2("changeme", salt);

                //set password if running in EC2
                File file = new File("/opt/bastillion/instance_id");
                if (file.exists()) {
                    String str = FileUtils.readFileToString(file, "UTF-8");
                    if (StringUtils.isNotEmpty(str)) {
                        defaultPassword = EncryptionUtil.hashV2(str.trim(), salt);
                    }
                }

                //insert default admin user
                PreparedStatement pStmt = connection.prepareStatement("insert into users (username, password, user_type, salt) values(?,?,?,?)");
                pStmt.setString(1, "admin");
                pStmt.setString(2, defaultPassword);
                pStmt.setString(3, Auth.MANAGER);
                pStmt.setString(4, salt);
                pStmt.execute();
                DBUtils.closeStmt(pStmt);

            }
            DBUtils.closeRs(rs);

            // Existing installations predate the interface-theme preference. H2's
            // IF NOT EXISTS makes this migration safe on every subsequent startup.
            statement.executeUpdate("alter table user_theme add column if not exists ui_theme varchar(5) not null default 'dark'");

            // Tables added in 6.0.0. Created here rather than in the fresh-install branch
            // above so that an existing installation picks them up on its next startup; all
            // three are "create table if not exists", so running them every time is a no-op
            // once they are there.
            //
            // Existing installations have no recorded host keys, which is why
            // hostKeyVerification defaults to accept-new rather than strict - an upgrade
            // records each host's key on its next connection instead of refusing every
            // connection until a manager has approved every host.
            statement.executeUpdate(CREATE_HOST_KEY_TABLE);
            statement.executeUpdate(CREATE_CERT_AUTHORITY_TABLE);
            statement.executeUpdate(CREATE_HOST_CERT_AUTHORITY_TABLE);

            // How the last connection to each system authenticated, so a certificate rollout
            // can be seen on the systems screen rather than only in the audit log. Null on
            // every existing row until that system is next connected to.
            statement.executeUpdate("alter table system add column if not exists last_auth_method varchar");

            // Generated whether or not certificate authentication is switched on: the public
            // half has to be installed on every managed system as TrustedUserCAKeys before the
            // feature can be enabled, so an operator has to be able to read it first. On its
            // own it grants nothing - nothing trusts this key until a host is told to.
            String caPublicKey = CertAuthorityDB.generateIfAbsent(CertAuthority.USER_CA);
            if (caPublicKey != null) {
                System.out.println("Bastillion Generated SSH User Certificate Authority Key:");
                System.out.println(caPublicKey);
                System.out.println("Install this on managed systems as TrustedUserCAKeys to use "
                        + "certificate authentication (sshCertificateAuth=on).");
            }

            //if reset ssh application key then generate new key
            if (resetSSHKey) {

                //delete old key entry
                PreparedStatement pStmt = connection.prepareStatement("delete from application_key");
                pStmt.execute();
                DBUtils.closeStmt(pStmt);

                //generate new key and insert passphrase
                System.out.println("Setting Bastillion SSH public/private key pair");

                //generate application pub/pvt key and get values
                String passphrase = SSHUtil.keyGen();
                String publicKey = SSHUtil.getPublicKey();
                String privateKey = SSHUtil.getPrivateKey();

                //insert new keys
                pStmt = connection.prepareStatement("insert into application_key (public_key, private_key, passphrase) values(?,?,?)");
                pStmt.setString(1, publicKey);
                pStmt.setString(2, EncryptionUtil.encrypt(privateKey));
                pStmt.setString(3, EncryptionUtil.encrypt(passphrase));
                pStmt.execute();
                DBUtils.closeStmt(pStmt);

                System.out.println("Bastillion Generated Global Public Key:");
                System.out.println(publicKey);

                //set config to default
                AppConfig.updateProperty("publicKey", "");
                AppConfig.updateProperty("privateKey", "");
                AppConfig.updateProperty("defaultSSHPassphrase", "${randomPassphrase}");

                //set to false
                AppConfig.updateProperty("resetApplicationSSHKey", "false");

            }

            // keyManagement=off means Bastillion never puts its key on a host, so with
            // certificate authentication also off it has no way to gain access to a system it
            // has not already been let into by hand. Worth saying out loud at startup rather
            // than leaving as a run of failed registrations.
            if (KeyManagement.mode() == KeyManagement.Mode.OFF && !SshCertificateAuth.isEnabled()) {
                String warning = "WARNING: keyManagement=off and sshCertificateAuth=off. Bastillion "
                        + "will not add its public key to any system, so a system is only reachable if "
                        + "its authorized_keys already contains the application key. Set "
                        + "sshCertificateAuth=on (and install the CA key on each host), or use "
                        + "keyManagement=append.";
                System.out.println(warning);
                log.error(warning);
            }

            // sshCertificateAuth only works with an Ed25519 application key, and sshKeyType
            // accepts rsa/ecdsa/ed448 too. Without this the mismatch is invisible: issuing
            // fails, connections quietly fall back to plain key authentication and keep
            // working, so nothing looks wrong until somebody wonders why no host ever logs a
            // certificate.
            if (SshCertificateAuth.isEnabled()) {
                ApplicationKey appKey = PrivateKeyDB.getApplicationKey();
                String unsupported = appKey == null ? null
                        : SshCertificateAuth.unsupportedKeyTypeReason(appKey.getPublicKey());
                if (unsupported != null) {
                    String warning = "WARNING: sshCertificateAuth=on. " + unsupported
                            + " Until then every connection silently falls back to plain public "
                            + "key authentication.";
                    System.out.println(warning);
                    log.error(warning);
                }
            }

            String validityWarning = SshCertificateAuth.excessiveValidityWarning();
            if (validityWarning != null) {
                System.out.println("WARNING: " + validityWarning);
                log.error(validityWarning);
            }

            //delete ssh keys
            SSHUtil.deletePvtGenSSHKey();

            DBUtils.closeStmt(statement);
            DBUtils.closeConn(connection);

        } catch (SQLException | ConfigurationException | InterruptedException| IOException | GeneralSecurityException | JSchException ex) {
            log.error(ex.toString(), ex);
            throw new ServletException(ex.toString(), ex);
        }

        RefreshAuthKeyUtil.startRefreshAllSystemsTimerTask();
    }

}
