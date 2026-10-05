/**
 * Copyright (C) 2013 Loophole, LLC
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EncryptionUtil {

    private static final Logger log = LoggerFactory.getLogger(EncryptionUtil.class);

    // Bastillion secret key material for app-level encryption
    private static byte[] key = new byte[0];

    static {
        try {
            key = KeyStoreUtil.getSecretBytes(KeyStoreUtil.ENCRYPTION_KEY_ALIAS);
        } catch (GeneralSecurityException ex) {
            log.error(ex.toString(), ex);
        }
    }

    // Algorithms / transforms
    public static final String CRYPT_ALGORITHM = "AES"; // key alg
    private static final String T_GCM = "AES/GCM/NoPadding";
    private static final String T_ECB = "AES/ECB/PKCS5Padding";          // legacy app encrypt (Cipher.getInstance("AES"))
    public static final String HASH_ALGORITHM = "SHA-256";

    // GCM params
    private static final int GCM_IV_LEN = 12;         // 96-bit IV recommended
    private static final int GCM_TAG_LEN_BITS = 128;  // 16-byte tag

    // Version marker for serialized ciphertexts
    private static final String V2_PREFIX = "v2:";    // GCM

    // Password hash versioning (PBKDF2 replaces legacy single-round SHA-256)
    private static final String HASH_V2_PREFIX = "pbkdf2:";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int HASH_V2_ITERATIONS = 210000; // OWASP-recommended minimum for PBKDF2-HMAC-SHA256
    private static final int HASH_V2_KEY_LEN_BITS = 256;

    private EncryptionUtil() {}

    // --------------------------------------------------------------------
    // Salt & Hash
    // --------------------------------------------------------------------
    public static String generateSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return new String(Base64.encodeBase64(salt));
    }

    /**
     * Legacy single-round SHA-256(password + salt) hash.
     * Kept only to verify passwords stored before the PBKDF2 migration (see {@link #hashV2}).
     */
    public static String hash(String str, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        if (StringUtils.isNotEmpty(salt)) {
            md.update(Base64.decodeBase64(salt.getBytes(StandardCharsets.UTF_8)));
        }
        md.update(str.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.encodeBase64(md.digest()), StandardCharsets.UTF_8);
    }

    public static String hash(String str) throws NoSuchAlgorithmException {
        return hash(str, null);
    }

    /**
     * Bastillion v4's actual login hash: AuthDB/UserDB/DBInitServlet there call
     * {@code EncryptionUtil.hash(password + salt)} - the single-arg overload, with the
     * stored (base64) salt string concatenated directly onto the plaintext password before
     * a single SHA-256 digest, rather than digesting salt and password as separate updates
     * like {@link #hash(String, String)} does. Same digest algorithm, different byte layout
     * - so it needs its own formula to verify passwords migrated from a real v4 database
     * (see tools/migrate/).
     */
    private static String hashV4Concat(String str, String salt) throws NoSuchAlgorithmException {
        return hash(str + (salt == null ? "" : salt));
    }

    /**
     * Current password hash: PBKDF2WithHmacSHA256, 210k iterations, prefixed "pbkdf2:" so it can be
     * told apart from a legacy single-round SHA-256 hash at verification time.
     */
    public static String hashV2(String str, String salt) throws GeneralSecurityException {
        byte[] saltBytes = StringUtils.isNotEmpty(salt) ? Base64.decodeBase64(salt) : new byte[0];
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(str.toCharArray(), saltBytes, HASH_V2_ITERATIONS, HASH_V2_KEY_LEN_BITS);
        SecretKey derived = factory.generateSecret(spec);
        return HASH_V2_PREFIX + new String(Base64.encodeBase64(derived.getEncoded()), StandardCharsets.UTF_8);
    }

    /**
     * Verifies a plaintext value against a stored hash, whatever format it was stored in:
     * PBKDF2 "pbkdf2:" v2, this app's own legacy single-round SHA-256 (salt and password
     * digested separately), or a real Bastillion v4 database's single-round SHA-256 (salt
     * concatenated onto the password first - see {@link #hashV4Concat}). Comparison is
     * constant-time.
     */
    public static boolean verifyHash(String plainText, String salt, String storedHash) throws GeneralSecurityException {
        if (StringUtils.isEmpty(storedHash) || StringUtils.isEmpty(plainText)) {
            return false;
        }
        if (storedHash.startsWith(HASH_V2_PREFIX)) {
            return constantTimeEquals(hashV2(plainText, salt), storedHash);
        }
        return constantTimeEquals(hash(plainText, salt), storedHash)
                || constantTimeEquals(hashV4Concat(plainText, salt), storedHash);
    }

    private static boolean constantTimeEquals(String candidate, String storedHash) {
        return MessageDigest.isEqual(
                candidate.getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * True if the stored hash is already in the current (v2) format.
     */
    public static boolean isLegacyHash(String storedHash) {
        return StringUtils.isNotEmpty(storedHash) && !storedHash.startsWith(HASH_V2_PREFIX);
    }

    // --------------------------------------------------------------------
    // Application-level encryption (now GCM v2 with legacy fallback)
    // --------------------------------------------------------------------
    public static String encrypt(byte[] rawKey, String plaintext) throws GeneralSecurityException {
        if (StringUtils.isEmpty(plaintext)) return null;

        byte[] iv = new byte[GCM_IV_LEN];
        new SecureRandom().nextBytes(iv);

        Cipher c = Cipher.getInstance(T_GCM);
        SecretKeySpec sk = new SecretKeySpec(rawKey, CRYPT_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LEN_BITS, iv);
        c.init(Cipher.ENCRYPT_MODE, sk, spec);

        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Serialize: v2: base64( iv || ct )
        ByteBuffer bb = ByteBuffer.allocate(iv.length + ct.length);
        bb.put(iv).put(ct);
        String b64 = java.util.Base64.getEncoder().encodeToString(bb.array());
        return V2_PREFIX + b64;
    }

    public static String decrypt(byte[] rawKey, String serialized) throws GeneralSecurityException {
        if (StringUtils.isEmpty(serialized)) return null;

        // Prefer v2 GCM
        if (serialized.startsWith(V2_PREFIX)) {
            String b64 = serialized.substring(V2_PREFIX.length());
            byte[] all = java.util.Base64.getDecoder().decode(b64);
            if (all.length < GCM_IV_LEN + 16) { // need room for tag too
                throw new GeneralSecurityException("ciphertext too short");
            }
            byte[] iv = new byte[GCM_IV_LEN];
            byte[] ct = new byte[all.length - GCM_IV_LEN];
            System.arraycopy(all, 0, iv, 0, GCM_IV_LEN);
            System.arraycopy(all, GCM_IV_LEN, ct, 0, ct.length);

            Cipher c = Cipher.getInstance(T_GCM);
            SecretKeySpec sk = new SecretKeySpec(rawKey, CRYPT_ALGORITHM);
            c.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(GCM_TAG_LEN_BITS, iv));
            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        }

        // Legacy fallback: old default "AES" (i.e., AES/ECB/PKCS5Padding)
        //
        // codeql[java/weak-cryptographic-algorithm]: decrypt-only fallback for ciphertext
        // written before the CBC->GCM migration (1501b09); encrypt() above only ever
        // writes v2 GCM. Values only get upgraded to v2 when rewritten (e.g. a password
        // change), so removing this would break decrypting already-stored dbPassword/
        // private_key/passphrase/otp_secret values on any deployment that upgraded but
        // hasn't rewritten them since.
        //
        // There is no further fallback to try. A pre-v2 CBC ciphertext carries no IV and no
        // metadata to recover one from, so it is unrecoverable by construction - this used to
        // be written out as a second "fallback" block whose entire body threw an exception
        // and caught its own throw to rethrow it unchanged.
        Cipher c = Cipher.getInstance(T_ECB);
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, CRYPT_ALGORITHM));
        byte[] decodedVal = Base64.decodeBase64(serialized.getBytes(StandardCharsets.UTF_8));
        return new String(c.doFinal(decodedVal), StandardCharsets.UTF_8);
    }

    public static String encrypt(String str) throws GeneralSecurityException {
        return encrypt(key, str);
    }

    public static String decrypt(String str) throws GeneralSecurityException {
        return decrypt(key, str);
    }
}
