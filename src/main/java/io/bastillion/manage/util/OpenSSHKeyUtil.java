/**
 * Copyright (C) 2013 Loophole, LLC
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * OpenSSH key formats: encoding public and private keys, fingerprints, key types, and
 * passphrase-wrapping a private key with ssh-keygen. Pure functions over key material -
 * nothing here opens a connection.
 */
public class OpenSSHKeyUtil {

    private static final Logger log = LoggerFactory.getLogger(OpenSSHKeyUtil.class);

    private OpenSSHKeyUtil() {
    }

    public static byte[] encodeSSHPublicKey(String keyType, byte[] rawPubBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeSSHString(out, keyType.getBytes(StandardCharsets.UTF_8));
        byte[] keyPart = extractRawKeyFromX509(rawPubBytes);
        writeSSHBytes(out, keyPart);
        return out.toByteArray();
    }

    public static String buildOpenSSHPrivateKey(Long userId, java.security.KeyPair kp, int type, String passphrase)
            throws IOException, GeneralSecurityException, InterruptedException {
        String unencryptedPEM = buildOpenSSHPrivateKey(kp, type);
        if (StringUtils.isBlank(passphrase)) return unencryptedPEM;
        return rewrapWithOpenSSHKeygen(userId != null ? userId.toString() : UUID.randomUUID().toString(),
                unencryptedPEM, passphrase);
    }

    public static String getFingerprint(String publicKey) {
        String fingerprint = null;
        if (StringUtils.isNotEmpty(publicKey)) {
            if (publicKey.contains("ssh-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ssh-"));
            } else if (publicKey.contains("ecdsa-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ecdsa-"));
            }
            try {
                KeyPair keyPair = KeyPair.load(new JSch(), null, publicKey.getBytes());
                if (keyPair != null) {
                    fingerprint = keyPair.getFingerPrint();
                }
            } catch (JSchException ex) {
                log.error(ex.toString(), ex);
            }
        }
        return fingerprint;
    }

    /**
     * Returns public key type from an OpenSSH public key string.
     * Recognizes DSA, RSA, ECDSA, ED25519, ED448.
     */
    public static String getKeyType(String publicKey) {
        String keyType = null;
        if (StringUtils.isNotEmpty(publicKey)) {
            // Normalize to start at the algorithm token
            if (publicKey.contains("ssh-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ssh-"));
            } else if (publicKey.contains("ecdsa-")) {
                publicKey = publicKey.substring(publicKey.indexOf("ecdsa-"));
            }
            try {
                KeyPair keyPair = KeyPair.load(new JSch(), null, publicKey.getBytes(StandardCharsets.UTF_8));
                if (keyPair != null) {
                    int type = keyPair.getKeyType();
                    if (KeyPair.DSA == type)        keyType = "DSA";
                    else if (KeyPair.RSA == type)    keyType = "RSA";
                    else if (KeyPair.ECDSA == type)  keyType = "ECDSA";
                    else if (KeyPair.ED25519 == type)keyType = "ED25519";
                    else if (KeyPair.ED448 == type)  keyType = "ED448";
                    else if (KeyPair.UNKNOWN == type)keyType = "UNKNOWN";
                    else if (KeyPair.ERROR == type)  keyType = "ERROR";
                }
            } catch (JSchException ex) {
                log.error(ex.toString(), ex);
            }
        }
        return keyType;
    }

    public static String buildOpenSSHPrivateKey(java.security.KeyPair kp, int type) throws IOException {
        String keyType = (type == KeyPair.ED25519) ? "ssh-ed25519" : "ssh-ed448";
        ByteArrayOutputStream outer = new ByteArrayOutputStream();
        outer.write("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII));
        writeSSHString(outer, "none".getBytes());
        writeSSHString(outer, "none".getBytes());
        writeSSHString(outer, new byte[0]);
        outer.write(ByteBuffer.allocate(4).putInt(1).array());

        ByteArrayOutputStream pubBlob = new ByteArrayOutputStream();
        writeSSHString(pubBlob, keyType.getBytes());
        byte[] pubRaw = extractRawKeyFromX509(kp.getPublic().getEncoded());
        writeSSHBytes(pubBlob, pubRaw);
        writeSSHBytes(outer, pubBlob.toByteArray());

        ByteArrayOutputStream privBlob = new ByteArrayOutputStream();
        int chk = new SecureRandom().nextInt();
        privBlob.write(ByteBuffer.allocate(4).putInt(chk).array());
        privBlob.write(ByteBuffer.allocate(4).putInt(chk).array());
        writeSSHString(privBlob, keyType.getBytes());
        writeSSHBytes(privBlob, pubRaw);

        byte[] privRaw = extractRawKeyFromX509(kp.getPrivate().getEncoded());
        if (keyType.equals("ssh-ed25519") && privRaw.length > 32)
            privRaw = Arrays.copyOfRange(privRaw, privRaw.length - 32, privRaw.length);
        ByteArrayOutputStream combo = new ByteArrayOutputStream();
        combo.write(privRaw);
        combo.write(pubRaw);
        writeSSHBytes(privBlob, combo.toByteArray());
        writeSSHString(privBlob, "".getBytes());
        int padLen = 8 - (privBlob.size() % 8);
        for (int i = 1; i <= padLen; i++) privBlob.write(i);
        writeSSHBytes(outer, privBlob.toByteArray());
        String base64 = Base64.getMimeEncoder(70, "\n".getBytes())
                .encodeToString(outer.toByteArray());
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64 +
                "\n-----END OPENSSH PRIVATE KEY-----\n";
    }

    static String generateOpenSSHPublicKey(java.security.KeyPair kp, String comment, int type) throws IOException {
        String algo = (type == KeyPair.ED25519) ? "ssh-ed25519" :
                (type == KeyPair.ED448) ? "ssh-ed448" : "ssh-unknown";
        byte[] rawPub = extractRawKeyFromX509(kp.getPublic().getEncoded());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeSSHString(out, algo.getBytes());
        writeSSHBytes(out, rawPub);
        String encoded = Base64.getEncoder().encodeToString(out.toByteArray());
        return algo + " " + encoded + " " + comment + "\n";
    }

    public static void writeSSHString(ByteArrayOutputStream out, byte[] data) throws IOException {
        out.write(ByteBuffer.allocate(4).putInt(data.length).array());
        out.write(data);
    }

    public static void writeSSHBytes(ByteArrayOutputStream out, byte[] bytes) throws IOException {
        out.write(ByteBuffer.allocate(4).putInt(bytes.length).array());
        out.write(bytes);
    }

    public static byte[] extractRawKeyFromX509(byte[] x509Encoded) {
        for (int i = 0; i < x509Encoded.length - 3; i++) {
            if (x509Encoded[i] == 0x03 && x509Encoded[i + 2] == 0x00)
                return Arrays.copyOfRange(x509Encoded, i + 3, x509Encoded.length);
        }
        return x509Encoded;
    }

    /**
     * ssh-keygen here is local and non-interactive and finishes in milliseconds. A process
     * still alive after this has stopped to prompt for something, and will never be answered.
     */
    private static final long KEYGEN_TIMEOUT_SECONDS = 30;

    private static final byte[] OPENSSH_KEY_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

    private static final String CIPHER_NONE = "none";

    /**
     * Re-encrypts a freshly generated OpenSSH private key under the user's passphrase, by
     * handing it to ssh-keygen.
     * <p>
     * Every failure here has to be loud. This runs on the path that generates a key for a
     * user to download ({@code AuthKeysKtrl.generateUserKey}), so the caller cannot tell a
     * rewrapped key from the plaintext one it passed in by looking at it - and the user is
     * told the result is protected by the passphrase they just chose. The previous version
     * called {@code proc.waitFor()}, discarded the exit status and returned the file
     * regardless, so any ssh-keygen failure returned the key still completely unencrypted.
     */
    public static String rewrapWithOpenSSHKeygen(String userId, String pem, String passphrase)
            throws IOException, InterruptedException, GeneralSecurityException {
        Path tmp = Files.createTempFile("bastillion_key_" + userId + "_", ".key");
        Files.write(tmp, pem.getBytes(StandardCharsets.US_ASCII));
        try {
            try {
                Files.setPosixFilePermissions(tmp, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException ignored) {}
            ProcessBuilder pb = new ProcessBuilder("ssh-keygen", "-p", "-P", "",
                    "-N", passphrase, "-f", tmp.toString(), "-o", "-a", "16");
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            // Close the child's stdin straight away. It is a pipe this end never writes to,
            // so had ssh-keygen decided to prompt - a wrong -P, a format it would rather ask
            // about - it would have blocked on a read that nothing was ever going to satisfy.
            // At EOF it fails and exits instead, which is what makes draining its output
            // below safe to do on this thread.
            proc.getOutputStream().close();

            // Read the merged output before waiting, not after. redirectErrorStream was
            // already set but nothing ever read the pipe, so output large enough to fill the
            // buffer would have left ssh-keygen blocked writing and waitFor() blocked on
            // ssh-keygen.
            String output;
            try (InputStream out = proc.getInputStream()) {
                output = new String(out.readAllBytes(), StandardCharsets.UTF_8).trim();
            }

            if (!proc.waitFor(KEYGEN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
                throw new GeneralSecurityException("ssh-keygen did not finish within "
                        + KEYGEN_TIMEOUT_SECONDS + "s while applying a passphrase to the generated key");
            }
            if (proc.exitValue() != 0) {
                throw new GeneralSecurityException("ssh-keygen failed (exit " + proc.exitValue()
                        + ") while applying a passphrase to the generated key"
                        + (output.isEmpty() ? "" : ": " + output));
            }

            String rewrapped = Files.readString(tmp, StandardCharsets.US_ASCII);
            // Check the property the user is relying on, rather than trusting the exit status
            // to imply it. This is the last point at which an unencrypted key can be stopped.
            if (!isEncryptedOpenSSHPrivateKey(rewrapped)) {
                throw new GeneralSecurityException(
                        "ssh-keygen reported success but the generated private key is not encrypted");
            }
            return rewrapped;
        } finally {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) {}
        }
    }

    /**
     * True if this is an OpenSSH private key whose contents are encrypted.
     * <p>
     * The openssh-key-v1 container names its cipher in the clear: the magic is followed by an
     * SSH string holding the cipher name, which is literally "none" for an unencrypted key
     * (see {@link #buildOpenSSHPrivateKey(java.security.KeyPair, int)}, which writes exactly
     * that). Anything whose format cannot be read is reported as not encrypted - this backs a
     * security check, so being unable to prove encryption counts as failing it.
     */
    static boolean isEncryptedOpenSSHPrivateKey(String pem) {
        if (StringUtils.isBlank(pem)) {
            return false;
        }
        String body = StringUtils.substringBetween(pem,
                "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----");
        if (body == null) {
            return false;
        }
        byte[] decoded;
        try {
            decoded = Base64.getMimeDecoder().decode(body);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (decoded.length < OPENSSH_KEY_MAGIC.length + 4) {
            return false;
        }
        if (!Arrays.equals(Arrays.copyOf(decoded, OPENSSH_KEY_MAGIC.length), OPENSSH_KEY_MAGIC)) {
            return false;
        }
        ByteBuffer buffer = ByteBuffer.wrap(decoded, OPENSSH_KEY_MAGIC.length,
                decoded.length - OPENSSH_KEY_MAGIC.length);
        int cipherLength = buffer.getInt();
        if (cipherLength < 0 || cipherLength > buffer.remaining()) {
            return false;
        }
        byte[] cipher = new byte[cipherLength];
        buffer.get(cipher);
        return !CIPHER_NONE.equals(new String(cipher, StandardCharsets.US_ASCII));
    }
}
