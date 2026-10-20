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
import io.bastillion.manage.util.ExternalAuthUtil;
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
            boolean freshInstall = !rs.next();
            DBUtils.closeRs(rs);

            //create or upgrade the schema - see SchemaMigrations
            SchemaMigrations.migrate(connection);

            if (freshInstall) {
                resetSSHKey = true;

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

            String userValidityWarning = SshCertificateAuth.excessiveUserValidityWarning();
            if (userValidityWarning != null) {
                System.out.println("WARNING: " + userValidityWarning);
                log.error(userValidityWarning);
            }

            String validityWarning = SshCertificateAuth.excessiveValidityWarning();
            if (validityWarning != null) {
                System.out.println("WARNING: " + validityWarning);
                log.error(validityWarning);
            }

            // An LDAP setup that cannot work - jaasModule naming no jaas.conf entry, or an entry
            // naming a login module class that is not there - otherwise only shows up as
            // every directory user being told they have the wrong password.
            String ldapProblem = ExternalAuthUtil.configurationProblem();
            if (ldapProblem != null) {
                String warning = "WARNING: LDAP login will fail: " + ldapProblem
                        + ". Until this is fixed only local accounts can sign in.";
                System.out.println(warning);
                log.error(warning);
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
