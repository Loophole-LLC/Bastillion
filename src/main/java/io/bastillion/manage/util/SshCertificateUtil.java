/**
 * Copyright (C) 2013 Loophole, LLC
 * <p>
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds and signs OpenSSH certificates, per PROTOCOL.certkeys.
 * <p>
 * Signing is done here in Java rather than by shelling out to {@code ssh-keygen -s}, which
 * would be less code. {@code ssh-keygen -s} can only read its CA key from a file, so every
 * signature would mean writing the certificate authority's private key to disk - and unlike
 * the application key, the CA key mints access to every host that trusts it, so it is the one
 * key in this system that should never leave memory. {@link SSHUtil#rewrapWithOpenSSHKeygen}
 * is the existing precedent for the temp-file approach and is fine for a user's own key; it is
 * not fine for this.
 * <p>
 * Ed25519 only. That is the key type Bastillion generates for itself
 * ({@code DBInitServlet}) and the default for user keys ({@code defaultUserKeyType}), and
 * confining the format work to one algorithm keeps the encoding small enough to be read and
 * checked against the spec. Signing a key of another type raises
 * {@link GeneralSecurityException} rather than producing something subtly wrong.
 */
public class SshCertificateUtil {

    public static final String ED25519_KEY_TYPE = "ssh-ed25519";
    public static final String ED25519_CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com";

    static final int SSH_CERT_TYPE_USER = 1;
    static final int SSH_CERT_TYPE_HOST = 2;

    private static final int ED25519_RAW_KEY_LENGTH = 32;
    private static final int ED25519_SEED_LENGTH = 32;
    private static final int CERT_NONCE_LENGTH = 32;

    /**
     * Certificates are backdated slightly so that a host whose clock trails Bastillion's does
     * not reject a certificate issued for a session starting right now.
     */
    private static final long CLOCK_SKEW_SECONDS = 60;

    /**
     * The single extension Bastillion's own sessions need: they open a shell on a pty. Port,
     * agent and X11 forwarding are deliberately not granted - a certificate carries whatever
     * it permits for its whole validity, and Bastillion never uses them.
     */
    private static final Map<String, String> SESSION_EXTENSIONS = Map.of("permit-pty", "");

    private static final byte[] OPENSSH_KEY_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);

    private SshCertificateUtil() {
    }

    /**
     * Signs an OpenSSH user certificate for an Ed25519 public key.
     *
     * @param caPrivateKeyPem  the CA private key, as an unencrypted openssh-key-v1 PEM
     * @param caPublicKey      the CA public key, in authorized_keys form
     * @param subjectPublicKey the public key to certify, in authorized_keys form
     * @param keyId            the certificate's key id - sshd logs this on every accepted
     *                         connection, which is what carries attribution to the host
     * @param principals       usernames this certificate may log in as; sshd accepts the
     *                         certificate if any one of them matches the target account
     * @param serial           certificate serial, logged by sshd alongside the key id
     * @param validitySeconds  how long the certificate is valid from now
     * @return the certificate in authorized_keys form:
     * {@code ssh-ed25519-cert-v01@openssh.com <base64> <keyId>}
     */
    public static String signUserCertificate(String caPrivateKeyPem, String caPublicKey,
                                             String subjectPublicKey, String keyId,
                                             Collection<String> principals, long serial,
                                             long validitySeconds) throws GeneralSecurityException {
        if (StringUtils.isBlank(keyId)) {
            throw new GeneralSecurityException("a certificate key id is required");
        }
        if (principals == null || principals.isEmpty()) {
            // A user certificate with no principals is valid per the spec and means "any
            // user", which is the opposite of what anything here wants.
            throw new GeneralSecurityException("a certificate needs at least one principal");
        }

        byte[] subjectRawKey = rawEd25519Key(publicKeyBlob(subjectPublicKey, "subject"), "subject");
        byte[] caBlob = publicKeyBlob(caPublicKey, "certificate authority");
        rawEd25519Key(caBlob, "certificate authority");
        PrivateKey caPrivateKey = ed25519PrivateKey(caPrivateKeyPem);

        long now = System.currentTimeMillis() / 1000L;
        byte[] body = certificateBody(subjectRawKey, caBlob, keyId, principals, serial,
                now - CLOCK_SKEW_SECONDS, now + validitySeconds);

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(caPrivateKey);
        signer.update(body);
        byte[] rawSignature = signer.sign();

        try {
            ByteArrayOutputStream signatureBlob = new ByteArrayOutputStream();
            writeString(signatureBlob, ED25519_KEY_TYPE.getBytes(StandardCharsets.UTF_8));
            writeString(signatureBlob, rawSignature);

            ByteArrayOutputStream certificate = new ByteArrayOutputStream();
            certificate.write(body);
            writeString(certificate, signatureBlob.toByteArray());

            return ED25519_CERT_TYPE + " "
                    + Base64.getEncoder().encodeToString(certificate.toByteArray()) + " " + keyId;
        } catch (IOException ex) {
            throw new GeneralSecurityException("could not assemble the certificate", ex);
        }
    }

    /**
     * Everything the signature covers: the certificate up to and including the signature key.
     */
    private static byte[] certificateBody(byte[] subjectRawKey, byte[] caBlob, String keyId,
                                          Collection<String> principals, long serial,
                                          long validAfter, long validBefore)
            throws GeneralSecurityException {
        try {
            byte[] nonce = new byte[CERT_NONCE_LENGTH];
            new SecureRandom().nextBytes(nonce);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeString(out, ED25519_CERT_TYPE.getBytes(StandardCharsets.UTF_8));
            writeString(out, nonce);
            writeString(out, subjectRawKey);
            writeUint64(out, serial);
            writeUint32(out, SSH_CERT_TYPE_USER);
            writeString(out, keyId.getBytes(StandardCharsets.UTF_8));
            writeString(out, principalsBlob(principals));
            writeUint64(out, validAfter);
            writeUint64(out, validBefore);
            // No critical options: source-address and force-command are the two that exist,
            // and Bastillion constrains neither.
            writeString(out, new byte[0]);
            writeString(out, optionsBlob(SESSION_EXTENSIONS));
            writeString(out, new byte[0]);
            writeString(out, caBlob);
            return out.toByteArray();
        } catch (IOException ex) {
            throw new GeneralSecurityException("could not encode the certificate body", ex);
        }
    }

    /**
     * A string holding a sequence of strings, one per principal.
     */
    private static byte[] principalsBlob(Collection<String> principals) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String principal : principals) {
            writeString(out, principal.getBytes(StandardCharsets.UTF_8));
        }
        return out.toByteArray();
    }

    /**
     * A string holding (name, data) pairs. PROTOCOL.certkeys requires them in lexical order by
     * name, so they are sorted here rather than trusting the caller's map ordering.
     */
    private static byte[] optionsBlob(Map<String, String> options) throws IOException {
        Map<String, String> ordered = new LinkedHashMap<>();
        options.keySet().stream().sorted().forEach(name -> ordered.put(name, options.get(name)));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Map.Entry<String, String> option : ordered.entrySet()) {
            writeString(out, option.getKey().getBytes(StandardCharsets.UTF_8));
            // Each value is itself wrapped as a string inside the data field; an empty value
            // is an empty data field, not a string containing "".
            if (option.getValue().isEmpty()) {
                writeString(out, new byte[0]);
            } else {
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                writeString(data, option.getValue().getBytes(StandardCharsets.UTF_8));
                writeString(out, data.toByteArray());
            }
        }
        return out.toByteArray();
    }

    // --- parsing ---

    /**
     * The base64 blob out of an authorized_keys-form public key.
     */
    static byte[] publicKeyBlob(String opensshPublicKey, String what) throws GeneralSecurityException {
        if (StringUtils.isBlank(opensshPublicKey)) {
            throw new GeneralSecurityException("the " + what + " public key is empty");
        }
        String[] fields = opensshPublicKey.trim().split("\\s+");
        if (fields.length < 2) {
            throw new GeneralSecurityException("the " + what + " public key is not in authorized_keys form");
        }
        try {
            return Base64.getDecoder().decode(fields[1]);
        } catch (IllegalArgumentException ex) {
            throw new GeneralSecurityException("the " + what + " public key is not valid base64", ex);
        }
    }

    /**
     * The raw 32-byte key out of an {@code ssh-ed25519} public key blob.
     */
    static byte[] rawEd25519Key(byte[] blob, String what) throws GeneralSecurityException {
        SshReader reader = new SshReader(blob);
        String keyType = reader.readStringAsText();
        if (!ED25519_KEY_TYPE.equals(keyType)) {
            throw new GeneralSecurityException("the " + what + " key is " + keyType
                    + "; only " + ED25519_KEY_TYPE + " can be used with certificates here");
        }
        byte[] rawKey = reader.readString();
        if (rawKey.length != ED25519_RAW_KEY_LENGTH) {
            throw new GeneralSecurityException("the " + what + " key is " + rawKey.length
                    + " bytes, expected " + ED25519_RAW_KEY_LENGTH);
        }
        return rawKey;
    }

    /**
     * Recovers an Ed25519 signing key from an unencrypted openssh-key-v1 PEM.
     * <p>
     * The CA key is held in the same form as every other key in this application so that it
     * can be backed up, exported and re-imported as an ordinary OpenSSH key. Its seed is the
     * first half of the private key field; Java has taken a raw Ed25519 seed through
     * {@link EdECPrivateKeySpec} since 15, so no third-party parser is needed.
     */
    static PrivateKey ed25519PrivateKey(String pem) throws GeneralSecurityException {
        byte[] seed = ed25519Seed(pem);
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        return factory.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
    }

    static byte[] ed25519Seed(String pem) throws GeneralSecurityException {
        if (StringUtils.isBlank(pem)) {
            throw new GeneralSecurityException("the certificate authority private key is empty");
        }
        String body = StringUtils.substringBetween(pem,
                "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----");
        if (body == null) {
            throw new GeneralSecurityException("the certificate authority private key is not an OpenSSH private key");
        }
        byte[] decoded;
        try {
            decoded = Base64.getMimeDecoder().decode(body);
        } catch (IllegalArgumentException ex) {
            throw new GeneralSecurityException("the certificate authority private key is not valid base64", ex);
        }
        if (decoded.length < OPENSSH_KEY_MAGIC.length
                || !Arrays.equals(Arrays.copyOf(decoded, OPENSSH_KEY_MAGIC.length), OPENSSH_KEY_MAGIC)) {
            throw new GeneralSecurityException("the certificate authority private key is not an openssh-key-v1 key");
        }

        SshReader reader = new SshReader(decoded, OPENSSH_KEY_MAGIC.length);
        String cipher = reader.readStringAsText();
        if (!"none".equals(cipher)) {
            // SSHUtil.isEncryptedOpenSSHPrivateKey reads the same field. The CA key is stored
            // encrypted at the column level by EncryptionUtil, so what arrives here is already
            // decrypted; a passphrase-protected key would need one supplied to sign anything.
            throw new GeneralSecurityException(
                    "the certificate authority private key is passphrase-protected (" + cipher + ")");
        }
        reader.readString();                       // kdfname
        reader.readString();                       // kdfoptions
        reader.readUint32();                       // number of keys
        reader.readString();                       // public key blob
        byte[] privateSection = reader.readString();

        SshReader priv = new SshReader(privateSection);
        priv.readUint32();                         // check1
        priv.readUint32();                         // check2
        String keyType = priv.readStringAsText();
        if (!ED25519_KEY_TYPE.equals(keyType)) {
            throw new GeneralSecurityException("the certificate authority key is " + keyType
                    + "; only " + ED25519_KEY_TYPE + " is supported");
        }
        priv.readString();                         // public key
        byte[] privateKey = priv.readString();     // seed || public key
        if (privateKey.length < ED25519_SEED_LENGTH) {
            throw new GeneralSecurityException("the certificate authority private key is malformed");
        }
        return Arrays.copyOf(privateKey, ED25519_SEED_LENGTH);
    }

    /**
     * The raw public key a certificate certifies - the key whose private half the session
     * actually authenticates with.
     */
    public static byte[] readCertifiedPublicKey(String certificate) throws GeneralSecurityException {
        SshReader reader = new SshReader(publicKeyBlob(certificate, "certificate"));
        reader.readString();                       // key type
        reader.readString();                       // nonce
        return reader.readString();
    }

    /**
     * The key id of a certificate in authorized_keys form. This is the field sshd writes to
     * its auth log for every accepted connection.
     */
    public static String readKeyId(String certificate) throws GeneralSecurityException {
        SshReader reader = new SshReader(publicKeyBlob(certificate, "certificate"));
        reader.readString();                       // key type
        reader.readString();                       // nonce
        reader.readString();                       // public key
        reader.readUint64();                       // serial
        reader.readUint32();                       // type
        return reader.readStringAsText();
    }

    /**
     * The serial of a certificate in authorized_keys form.
     */
    public static long readSerial(String certificate) throws GeneralSecurityException {
        SshReader reader = new SshReader(publicKeyBlob(certificate, "certificate"));
        reader.readString();                       // key type
        reader.readString();                       // nonce
        reader.readString();                       // public key
        return reader.readUint64();
    }

    /**
     * The principals of a certificate in authorized_keys form, for display and for tests.
     */
    public static List<String> readPrincipals(String certificate) throws GeneralSecurityException {
        SshReader reader = new SshReader(publicKeyBlob(certificate, "certificate"));
        reader.readString();                       // key type
        reader.readString();                       // nonce
        reader.readString();                       // public key
        reader.readUint64();                       // serial
        reader.readUint32();                       // type
        reader.readString();                       // key id
        SshReader principals = new SshReader(reader.readString());
        List<String> names = new ArrayList<>();
        while (principals.hasRemaining()) {
            names.add(principals.readStringAsText());
        }
        return names;
    }

    // --- wire primitives ---

    private static void writeString(ByteArrayOutputStream out, byte[] data) throws IOException {
        writeUint32(out, data.length);
        out.write(data);
    }

    private static void writeUint32(ByteArrayOutputStream out, int value) throws IOException {
        out.write(ByteBuffer.allocate(4).putInt(value).array());
    }

    private static void writeUint64(ByteArrayOutputStream out, long value) throws IOException {
        out.write(ByteBuffer.allocate(8).putLong(value).array());
    }

    /**
     * Sequential reader for the SSH wire encoding, which is length-prefixed throughout.
     * Every read is bounds-checked: the blobs parsed here include certificates presented by
     * other parties.
     */
    private static final class SshReader {

        private final byte[] data;
        private int offset;

        SshReader(byte[] data) {
            this(data, 0);
        }

        SshReader(byte[] data, int offset) {
            this.data = data;
            this.offset = offset;
        }

        boolean hasRemaining() {
            return offset < data.length;
        }

        int readUint32() throws GeneralSecurityException {
            require(4);
            int value = ByteBuffer.wrap(data, offset, 4).getInt();
            offset += 4;
            return value;
        }

        long readUint64() throws GeneralSecurityException {
            require(8);
            long value = ByteBuffer.wrap(data, offset, 8).getLong();
            offset += 8;
            return value;
        }

        byte[] readString() throws GeneralSecurityException {
            int length = readUint32();
            if (length < 0) {
                throw new GeneralSecurityException("malformed SSH data: negative length");
            }
            require(length);
            byte[] value = Arrays.copyOfRange(data, offset, offset + length);
            offset += length;
            return value;
        }

        String readStringAsText() throws GeneralSecurityException {
            return new String(readString(), StandardCharsets.UTF_8);
        }

        private void require(int bytes) throws GeneralSecurityException {
            if (data.length - offset < bytes) {
                throw new GeneralSecurityException("malformed SSH data: truncated");
            }
        }
    }
}
