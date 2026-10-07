package io.bastillion.common.util;

import io.bastillion.manage.util.EncryptionUtil;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Properties;

/**
 * Utility to look up configurable commands and resources. Environment variables are
 * preferred (see getProperty) - BastillionConfig.properties / CONFIG_DIR exist mainly for
 * backward compatibility and for values that get persisted at runtime (e.g. a
 * DBInitServlet-generated dbPassword).
 */
public class AppConfig {

    private static final Logger log = LoggerFactory.getLogger(AppConfig.class);
    private static PropertiesConfiguration prop;

    public static final String CONFIG_DIR = normalizeDir(resolveConfigDir());

    // Whether CONFIG_DIR was explicitly requested (env var or -DCONFIG_DIR), as opposed to
    // falling back to defaultConfigDir() - drives which legacy-location migration applies
    // below (moving classpath-bundled config in vs. moving old working-directory state in).
    private static final boolean CONFIG_DIR_EXPLICIT =
            StringUtils.isNotEmpty(System.getProperty("CONFIG_DIR"))
                    || StringUtils.isNotEmpty(System.getenv("CONFIG_DIR"));

    private static FileBasedConfigurationBuilder<PropertiesConfiguration> builder;

    // Bundled defaults (BastillionConfig.properties as shipped on the classpath - always
    // present, read-only). Final fallback in getProperty() so unset-anywhere properties
    // (e.g. maxActive) still resolve without requiring a file on disk.
    private static final Properties DEFAULTS = loadDefaults();

    private static Properties loadDefaults() {
        Properties defaults = new Properties();
        try (InputStream in = AppConfig.class.getClassLoader().getResourceAsStream("BastillionConfig.properties")) {
            if (in != null) {
                defaults.load(in);
            }
        } catch (IOException ex) {
            log.error("Error loading bundled default configuration", ex);
        }
        return defaults;
    }

    static {
        try {
            if (CONFIG_DIR_EXPLICIT) {
                // Explicit CONFIG_DIR (env var or -DCONFIG_DIR): move config bundled on the
                // classpath (the old pre-CONFIG_DIR default location) into it if not already
                // there.
                URL classpathDir = AppConfig.class.getClassLoader().getResource(".");
                if (classpathDir != null) {
                    File classpathDirFile = new File(classpathDir.getPath());
                    moveIfAbsent("BastillionConfig.properties", classpathDirFile);
                    moveIfAbsent("jaas.conf", classpathDirFile);
                }
            } else {
                // No CONFIG_DIR override - we're on the "config" subdirectory default.
                // Releases before that default existed persisted everything straight in the
                // working directory; auto-migrate on upgrade so an in-place restart doesn't
                // orphan a generated keystore/db password (and silently regenerate them) or
                // strand the SSH host key pair / H2 database.
                File legacyDir = new File(System.getProperty("user.dir"));
                moveIfAbsent("BastillionConfig.properties", legacyDir);
                moveIfAbsent("jaas.conf", legacyDir);
                moveIfAbsent("bastillion.jceks", legacyDir);
                moveDirIfAbsent("keydb", legacyDir);
                moveDirIfAbsent("keystore", legacyDir);
            }

            // Build Commons Configuration 2.x-compatible builder. allowFailOnInit=true so a
            // missing BastillionConfig.properties (the expected case when running purely
            // off environment variables) starts an empty in-memory config instead of
            // throwing - getProperty() falls back to env vars regardless.
            Parameters params = new Parameters();
            builder = new FileBasedConfigurationBuilder<>(PropertiesConfiguration.class, null, true)
                    .configure(params.properties()
                            .setFileName(CONFIG_DIR + "BastillionConfig.properties")
                            .setEncoding("UTF-8"));

            prop = builder.getConfiguration();

        } catch (ConfigurationException | IOException ex) {
            log.error("Error loading configuration: " + ex, ex);
        }
    }

    private static String resolveConfigDir() {
        if (StringUtils.isNotEmpty(System.getProperty("CONFIG_DIR"))) {
            return System.getProperty("CONFIG_DIR").trim();
        }
        if (StringUtils.isNotEmpty(System.getenv("CONFIG_DIR"))) {
            return System.getenv("CONFIG_DIR").trim();
        }
        return defaultConfigDir();
    }

    /**
     * A "config" subdirectory of the working directory, whether running from the packaged
     * jar or unshaded (mvn compile exec:java). Deliberately NOT the classpath's "." resource
     * (target/classes when unshaded) - that's build output Maven freely overwrites on every
     * compile, which silently wiped runtime-persisted values like a generated keystore
     * password. getProperty() prefers environment variables anyway; a properties file here
     * is opt-in. Everything else that anchors to CONFIG_DIR (KEYSTORE_PATH's default, the H2
     * db via h2.baseDir, the SSH host key pair, bastillion.jceks) falls under the same root
     * automatically - set CONFIG_DIR once (env var or -DCONFIG_DIR) to relocate all of it.
     */
    private static String defaultConfigDir() {
        // Resolved to an absolute path (not a bare "config/" relative literal) because H2
        // requires an absolute h2.baseDir (see DSPool) to accept the bundled default
        // dbConnectionURL's relative "keydb/bastillion" - a relative baseDir doesn't satisfy
        // H2's "implicit relative path" check.
        return new File(System.getProperty("user.dir"), "config").getAbsolutePath() + File.separator;
    }

    // CONFIG_DIR is concatenated directly with filenames (see the FileBasedConfigurationBuilder
    // setup below) - normalize here so a user-supplied -DCONFIG_DIR without a trailing slash
    // doesn't silently merge into the filename.
    private static String normalizeDir(String dir) {
        return dir.endsWith(File.separator) ? dir : dir + File.separator;
    }

    private static void moveIfAbsent(String filename, File sourceDir) throws IOException {
        File newFile = new File(CONFIG_DIR, filename);
        if (newFile.exists()) {
            return;
        }
        File oldFile = new File(sourceDir, filename);
        if (oldFile.exists()) {
            FileUtils.moveFile(oldFile, newFile);
        }
    }

    private static void moveDirIfAbsent(String dirName, File sourceDir) throws IOException {
        File newDir = new File(CONFIG_DIR, dirName);
        if (newDir.exists()) {
            return;
        }
        File oldDir = new File(sourceDir, dirName);
        if (oldDir.isDirectory()) {
            FileUtils.moveDirectory(oldDir, newDir);
        }
    }

    private AppConfig() {
    }

    public static String getProperty(String name) {
        if (StringUtils.isEmpty(name)) {
            return null;
        }

        // First check environment variables: exact name, then camelCase converted to
        // SCREAMING_SNAKE_CASE (licenseKey -> LICENSE_KEY, dbUser -> DB_USER, ...), then the
        // same with acronyms split off the word that follows them, which is how anyone
        // actually writes them (defaultSSHPassphrase -> DEFAULT_SSH_PASSPHRASE).
        String property = System.getenv(name);
        if (StringUtils.isEmpty(property)) {
            property = System.getenv(toScreamingSnakeCase(name));
        }
        if (StringUtils.isEmpty(property)) {
            String acronymAware = toScreamingSnakeCaseSplittingAcronyms(name);
            property = System.getenv(acronymAware);
        }

        // Fallback to properties file, then to the bundled defaults
        if (StringUtils.isEmpty(property)) {
            property = prop.getString(name);
        }
        if (StringUtils.isEmpty(property)) {
            property = DEFAULTS.getProperty(name);
        }

        return property;
    }

    /**
     * Converts a camelCase property name to the SCREAMING_SNAKE_CASE convention used for
     * its environment variable override, e.g. licenseKey -> LICENSE_KEY, dbUser -> DB_USER.
     * <p>
     * A run of capitals stays glued to whatever follows it, so defaultSSHPassphrase becomes
     * DEFAULT_SSHPASSPHRASE rather than DEFAULT_SSH_PASSPHRASE. That is the historical name
     * and is still accepted; {@link #toScreamingSnakeCaseSplittingAcronyms} produces the one
     * an operator would actually guess, and both are looked up.
     */
    static String toScreamingSnakeCase(String camelCase) {
        return camelCase.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toUpperCase();
    }

    /**
     * As {@link #toScreamingSnakeCase}, but also breaks a run of capitals away from the word
     * it runs into: defaultSSHPassphrase -> DEFAULT_SSH_PASSPHRASE, clientIPHeader ->
     * CLIENT_IP_HEADER, resetApplicationSSHKey -> RESET_APPLICATION_SSH_KEY.
     * <p>
     * Both spellings are accepted because the documented name and the derived one had drifted
     * apart: the README told operators to export DEFAULT_SSH_PASSPHRASE and
     * RESET_APPLICATION_SSH_KEY, neither of which the single rule above produces, so those
     * settings were read from the properties file as though never set. Silently ignoring a
     * configured passphrase or key reset is worse than either spelling being wrong.
     */
    static String toScreamingSnakeCaseSplittingAcronyms(String camelCase) {
        return camelCase
                .replaceAll("([A-Z]+)([A-Z][a-z])", "$1_$2")
                .replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                .toUpperCase();
    }

    public static String getProperty(String name, String defaultValue) {
        String value = getProperty(name);
        return StringUtils.isEmpty(value) ? defaultValue : value;
    }

    public static String getProperty(String name, Map<String, String> replacementMap) {
        String value = getProperty(name);
        if (StringUtils.isNotEmpty(value)) {
            for (Map.Entry<String, String> entry : replacementMap.entrySet()) {
                value = value.replace("${" + entry.getKey() + "}", entry.getValue());
            }
        }
        return value;
    }

    public static void updateProperty(String name, String value) throws ConfigurationException {
        if (StringUtils.isNotEmpty(value)) {
            prop.setProperty(name, value);
            builder.save();
        }
    }

    public static boolean isPropertyEncrypted(String name) {
        String property = prop.getString(name);
        return StringUtils.isNotEmpty(property) && property.matches("^" + EncryptionUtil.CRYPT_ALGORITHM + "\\{.*\\}$");
    }

    public static String decryptProperty(String name) throws GeneralSecurityException {
        String retVal = prop.getString(name);
        if (StringUtils.isNotEmpty(retVal)) {
            retVal = retVal.replaceAll("^" + EncryptionUtil.CRYPT_ALGORITHM + "\\{", "")
                    .replaceAll("\\}$", "");
            retVal = EncryptionUtil.decrypt(retVal);
        }
        return retVal;
    }

    public static void encryptProperty(String name, String value)
            throws ConfigurationException, GeneralSecurityException {
        if (StringUtils.isNotEmpty(value)) {
            prop.setProperty(name, EncryptionUtil.CRYPT_ALGORITHM + "{" + EncryptionUtil.encrypt(value) + "}");
            builder.save();
        }
    }
}
