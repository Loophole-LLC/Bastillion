/**
 * Copyright (C) 2013 Loophole, LLC
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.*;
import io.bastillion.manage.db.*;
import io.bastillion.manage.model.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Reads and rewrites a host's authorized_keys over SFTP, and the checks on what goes into it.
 */
public class AuthorizedKeysUtil {

    private static final Logger log = LoggerFactory.getLogger(AuthorizedKeysUtil.class);

    private AuthorizedKeysUtil() {
    }

    // addPubKey reads and writes authorized_keys over SFTP, so neither of these values is
    // ever handed to a remote shell and neither guard is load-bearing against command
    // injection any more (see addPubKey). They are kept as input validation: a plain
    // relative/absolute path, and key lines that cannot corrupt the file they are written
    // into. Rejecting shell metacharacters is now purely defense-in-depth, in case a value
    // ever reaches an unquoted shell context again.
    private static final Pattern SAFE_AUTHORIZED_KEYS_PATH = Pattern.compile("[A-Za-z0-9_./-]+");

    // A CR or LF inside a single key line would split it into two authorized_keys entries,
    // letting a crafted key comment append an entry of its own with its own options (command=,
    // from=). That is the whole risk now: the file is written over SFTP, so no shell ever sees
    // these bytes.
    //
    // This deliberately no longer rejects shell metacharacters. It used to, from when each key
    // was interpolated into echo '...', and the cost was silent: an apostrophe is ordinary in a
    // key comment ("alice's laptop"), and such a key was dropped from authorized_keys with only
    // a line in the server log - the user simply found they had no access.
    private static final Pattern UNSAFE_KEY_CHARS = Pattern.compile("[\\r\\n]");

    // package-private (rather than private) so SSHUtilTest can exercise the guards directly
    static boolean isSafeAuthorizedKeysPath(String path) {
        return StringUtils.isNotBlank(path) && SAFE_AUTHORIZED_KEYS_PATH.matcher(path).matches();
    }

    static boolean isSafeKeyContent(String key) {
        return StringUtils.isNotBlank(key) && !UNSAFE_KEY_CHARS.matcher(key).find();
    }

    public static HostSystem addPubKey(HostSystem hostSystem, Session session, String appPublicKey) {
        if (!KeyManagement.writesAuthorizedKeys()) {
            // keyManagement=off: the host's authorized_keys is not ours to touch. Reaching
            // here at all means authentication already succeeded by some other means, which
            // in practice is an SSH certificate - so there is nothing to add and nothing to
            // reconcile. Status is left as the caller set it.
            return hostSystem;
        }
        try {
            String authorizedKeys = hostSystem.getAuthorizedKeys().replaceAll("~\\/|~", "");
            if (!isSafeAuthorizedKeysPath(authorizedKeys)) {
                log.error("Refusing to push keys for system {}: authorized_keys path '{}' contains disallowed characters",
                        hostSystem.getId(), authorizedKeys);
                hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
                return hostSystem;
            }

            String existingKeys = readAuthorizedKeys(session, authorizedKeys);
            String appPubKey = appPublicKey.replace("\n", "").trim();
            if (!isSafeKeyContent(appPubKey)) {
                log.error("Refusing to push keys for system {}: application public key contains disallowed characters",
                        hostSystem.getId());
                hostSystem.setStatusCd(HostSystem.GENERIC_FAIL_STATUS);
                return hostSystem;
            }

            String newKeys;
            if (SSHUtil.keyManagementEnabled) {
                List<String> assigned = PublicKeyDB.getPublicKeysForSystem(hostSystem.getId());
                StringBuilder sb = new StringBuilder();
                for (String k : assigned) {
                    String key = k.replace("\n", "").trim();
                    if (!isSafeKeyContent(key)) {
                        log.error("Skipping public key for system {}: key contains disallowed characters", hostSystem.getId());
                        continue;
                    }
                    sb.append(key).append("\n");
                }
                sb.append(appPubKey).append("\n");
                newKeys = sb.toString();
            } else {
                // Key management off: leave whatever is already on the host alone and just
                // make sure Bastillion's own key is present. existingKeys is host-controlled
                // content that is written straight back out, which is safe only because
                // writeAuthorizedKeys uses SFTP rather than a shell command.
                if (!existingKeys.contains(appPubKey))
                    newKeys = appendKeyLine(existingKeys, appPubKey);
                else newKeys = existingKeys;
            }

            if (!newKeys.equals(existingKeys)) {
                writeAuthorizedKeys(session, authorizedKeys, newKeys);
            }
        } catch (Exception ex) {
            log.error(ex.toString(), ex);
        }
        return hostSystem;
    }

    /**
     * Appends one key as a line of its own to existing authorized_keys content.
     * <p>
     * Every line, including the last, ends with a newline. OpenSSH reads a final line without
     * one perfectly well, but anything that later appends to the file - another configuration
     * tool, or an administrator running {@code echo key >> authorized_keys} - would run its
     * entry onto the end of Bastillion's, silently invalidating both. Coexisting with whatever
     * else manages the file is the entire point of keyManagement=append, so the file is left
     * in a state that is safe to append to.
     */
    static String appendKeyLine(String existingKeys, String key) {
        StringBuilder sb = new StringBuilder(existingKeys);
        if (!existingKeys.isEmpty() && !existingKeys.endsWith("\n")) {
            sb.append("\n");
        }
        return sb.append(key).append("\n").toString();
    }

    /**
     * Reads the remote authorized_keys file over SFTP, returning "" if it does not exist yet.
     * <p>
     * Deliberately not {@code cat <path>} over an exec channel: the contents come back here
     * and are written out again by {@link #writeAuthorizedKeys}, and routing them through a
     * shell command line meant any quote already present in the file (an apostrophe in a key
     * comment is perfectly legal) could terminate the quoting of the command that rewrote it.
     * SFTP transfers the bytes with no shell on either end, so the file's existing contents
     * need no escaping or validation at all.
     */
    private static String readAuthorizedKeys(Session session, String authorizedKeys) throws JSchException, SftpException, IOException {
        ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
        try {
            sftp.connect(SSHUtil.CHANNEL_TIMEOUT);
            try (InputStream in = sftp.get(authorizedKeys)) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            } catch (SftpException ex) {
                if (ex.id == ChannelSftp.SSH_FX_NO_SUCH_FILE) {
                    return "";
                }
                throw ex;
            }
        } finally {
            sftp.disconnect();
        }
    }

    /**
     * Suffix for the file the new authorized_keys is staged in. Beside the real one, so the
     * rename below stays within a single filesystem and can be atomic.
     */
    private static final String AUTHORIZED_KEYS_TMP_SUFFIX = ".bastillion-new";

    /**
     * Replaces the remote authorized_keys file over SFTP, via a staged write and a rename.
     * <p>
     * Writing straight over it would truncate first and stream after, so a connection lost
     * part way leaves a half-written or empty file - and in keyManagement=manage that file is
     * rewritten on every host by the refresh timer, unattended, every authKeysRefreshInterval
     * minutes. Losing it takes the application key with it, which locks Bastillion and every
     * user out of that host until somebody fixes it by hand. Staging and renaming means the
     * host has either the old file or the new one.
     */
    private static void writeAuthorizedKeys(Session session, String authorizedKeys, String contents) throws JSchException, SftpException {
        ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
        String staged = authorizedKeys + AUTHORIZED_KEYS_TMP_SUFFIX;
        try {
            sftp.connect(SSHUtil.CHANNEL_TIMEOUT);
            sftp.put(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)), staged);
            sftp.chmod(0600, staged);

            boolean renamed = false;
            boolean originalRemoved = false;
            try {
                try {
                    sftp.rename(staged, authorizedKeys);
                    renamed = true;
                } catch (SftpException ex) {
                    // SFTP version 3 leaves renaming onto an existing path undefined and
                    // servers without the posix-rename@openssh.com extension refuse it.
                    // Removing first reopens a window where the file is missing, but a far
                    // narrower one than streaming the whole file over the top of it.
                    log.info("Atomic rename of {} not available, falling back to replace", authorizedKeys);
                    sftp.rm(authorizedKeys);
                    originalRemoved = true;
                    sftp.rename(staged, authorizedKeys);
                    renamed = true;
                }
            } finally {
                // Only tidy the staged file away when doing so cannot destroy the last copy.
                // Having removed the original and then failed to rename, the staged file is
                // the only authorized_keys this host has - deleting it here would leave the
                // host with none at all, which is the lockout this whole method exists to
                // avoid. Leave it and say exactly where it is.
                if (!renamed && originalRemoved) {
                    log.error("Left the new authorized_keys at {} on this host: it could not be "
                                    + "renamed into place and {} has already been removed, so that "
                                    + "staged file is now the only copy. Move it into place to "
                                    + "restore access.", staged, authorizedKeys);
                } else if (!renamed) {
                    try {
                        sftp.rm(staged);
                    } catch (Exception ignored) {
                        // Best effort: the original is still intact either way.
                    }
                }
            }
        } finally {
            sftp.disconnect();
        }
    }
}
