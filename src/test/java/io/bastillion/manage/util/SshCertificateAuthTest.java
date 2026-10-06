/**
 * Copyright (C) 2013 Loophole, LLC
 *
 * Licensed under The Prosperity Public License 3.0.0
 */
package io.bastillion.manage.util;

import com.jcraft.jsch.KeyPair;
import io.bastillion.manage.db.CertAuthorityDB;
import io.bastillion.manage.db.PrivateKeyDB;
import io.bastillion.manage.model.ApplicationKey;
import io.bastillion.manage.model.CertAuthority;
import io.bastillion.manage.model.HostSystem;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

/**
 * What ends up inside the certificate Bastillion authenticates with. The two fields that
 * matter operationally are the principals, which decide whether sshd will accept it at all,
 * and the key id, which is what the host's own auth log records - the only thing that
 * attributes a session to a Bastillion user on the host side, since every connection
 * otherwise uses the one shared application key.
 */
class SshCertificateAuthTest {

    private static java.security.KeyPair newKeyPair() throws Exception {
        return java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static String publicKey(java.security.KeyPair kp, String comment) throws Exception {
        return "ssh-ed25519 " + Base64.getEncoder().encodeToString(
                SSHUtil.encodeSSHPublicKey("ssh-ed25519", kp.getPublic().getEncoded())) + " " + comment;
    }

    private record Fixture(CertAuthority ca, ApplicationKey appKey) {
    }

    private static Fixture fixture() throws Exception {
        java.security.KeyPair caKp = newKeyPair();
        CertAuthority ca = new CertAuthority();
        ca.setType(CertAuthority.USER_CA);
        ca.setPrivateKey(SSHUtil.buildOpenSSHPrivateKey(caKp, KeyPair.ED25519));
        ca.setPublicKey(publicKey(caKp, "bastillion-user-ca"));

        java.security.KeyPair appKp = newKeyPair();
        ApplicationKey appKey = new ApplicationKey();
        appKey.setId(1L);
        appKey.setPublicKey(publicKey(appKp, "bastillion@global_key"));
        appKey.setPrivateKey(SSHUtil.buildOpenSSHPrivateKey(appKp, KeyPair.ED25519));
        return new Fixture(ca, appKey);
    }

    private static HostSystem system(String loginAccount) {
        HostSystem hostSystem = new HostSystem();
        hostSystem.setId(7L);
        hostSystem.setHost("web01.example.com");
        hostSystem.setPort(22);
        hostSystem.setUser(loginAccount);
        return hostSystem;
    }

    @Test
    void namesTheBastillionUserInTheKeyIdThatTheHostWillLog() throws Exception {
        Fixture f = fixture();
        try (MockedStatic<CertAuthorityDB> caDb = mockStatic(CertAuthorityDB.class);
             MockedStatic<PrivateKeyDB> keyDb = mockStatic(PrivateKeyDB.class)) {
            caDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(f.ca());
            caDb.when(() -> CertAuthorityDB.nextSerial(anyString())).thenReturn(99L);
            keyDb.when(PrivateKeyDB::getApplicationKey).thenReturn(f.appKey());

            String certificate = SshCertificateAuth.issueCertificate(system("deploy"), "alice");

            assertEquals("bastillion:alice", SshCertificateUtil.readKeyId(certificate));
            assertEquals(99L, SshCertificateUtil.readSerial(certificate));
        }
    }

    @Test
    void fallsBackToASystemKeyIdWhenNoUserIsBehindTheConnection() throws Exception {
        // The authorized-key refresh timer and registering a system have no Bastillion user.
        Fixture f = fixture();
        try (MockedStatic<CertAuthorityDB> caDb = mockStatic(CertAuthorityDB.class);
             MockedStatic<PrivateKeyDB> keyDb = mockStatic(PrivateKeyDB.class)) {
            caDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(f.ca());
            caDb.when(() -> CertAuthorityDB.nextSerial(anyString())).thenReturn(1L);
            keyDb.when(PrivateKeyDB::getApplicationKey).thenReturn(f.appKey());

            String certificate = SshCertificateAuth.issueCertificate(system("deploy"), null);

            assertEquals("bastillion:system", SshCertificateUtil.readKeyId(certificate));
        }
    }

    @Test
    void theTargetAccountIsAPrincipalSoSshdWillAcceptTheCertificate() throws Exception {
        // sshd requires a principal matching the account being logged into, unless an
        // AuthorizedPrincipalsFile says otherwise - needing one of those per host would make
        // this unusable without further setup on every system.
        Fixture f = fixture();
        try (MockedStatic<CertAuthorityDB> caDb = mockStatic(CertAuthorityDB.class);
             MockedStatic<PrivateKeyDB> keyDb = mockStatic(PrivateKeyDB.class)) {
            caDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(f.ca());
            caDb.when(() -> CertAuthorityDB.nextSerial(anyString())).thenReturn(1L);
            keyDb.when(PrivateKeyDB::getApplicationKey).thenReturn(f.appKey());

            String certificate = SshCertificateAuth.issueCertificate(system("deploy"), "alice");

            assertEquals(List.of("deploy"), SshCertificateUtil.readPrincipals(certificate));
        }
    }

    @Test
    void certifiesTheApplicationKeyNotTheAuthorityKey() throws Exception {
        // A certificate attests to a key; the session still authenticates with the application
        // private key, so the certified public key has to be the application's.
        Fixture f = fixture();
        try (MockedStatic<CertAuthorityDB> caDb = mockStatic(CertAuthorityDB.class);
             MockedStatic<PrivateKeyDB> keyDb = mockStatic(PrivateKeyDB.class)) {
            caDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(f.ca());
            caDb.when(() -> CertAuthorityDB.nextSerial(anyString())).thenReturn(1L);
            keyDb.when(PrivateKeyDB::getApplicationKey).thenReturn(f.appKey());

            String certificate = SshCertificateAuth.issueCertificate(system("deploy"), "alice");

            byte[] certified = SshCertificateUtil.readCertifiedPublicKey(certificate);
            byte[] applicationKey = SshCertificateUtil.rawEd25519Key(
                    SshCertificateUtil.publicKeyBlob(f.appKey().getPublicKey(), "app"), "app");
            byte[] authorityKey = SshCertificateUtil.rawEd25519Key(
                    SshCertificateUtil.publicKeyBlob(f.ca().getPublicKey(), "ca"), "ca");

            assertArrayEquals(applicationKey, certified);
            assertFalse(java.util.Arrays.equals(authorityKey, certified));
        }
    }

    @Test
    void returnsNothingWhenNoAuthorityHasBeenGenerated() throws Exception {
        // Falling back to plain key authentication beats failing every connection.
        Fixture f = fixture();
        try (MockedStatic<CertAuthorityDB> caDb = mockStatic(CertAuthorityDB.class);
             MockedStatic<PrivateKeyDB> keyDb = mockStatic(PrivateKeyDB.class)) {
            caDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(null);

            assertNull(SshCertificateAuth.issueCertificate(system("deploy"), "alice"));
        }
    }

    @Test
    void returnsNothingWhenTheSystemHasNoLoginAccount() throws Exception {
        Fixture f = fixture();
        try (MockedStatic<CertAuthorityDB> caDb = mockStatic(CertAuthorityDB.class);
             MockedStatic<PrivateKeyDB> keyDb = mockStatic(PrivateKeyDB.class)) {
            caDb.when(() -> CertAuthorityDB.getCertAuthority(CertAuthority.USER_CA)).thenReturn(f.ca());
            caDb.when(() -> CertAuthorityDB.nextSerial(anyString())).thenReturn(1L);
            keyDb.when(PrivateKeyDB::getApplicationKey).thenReturn(f.appKey());

            assertNull(SshCertificateAuth.issueCertificate(system(null), "alice"));
        }
    }

    @Test
    void isOffByDefault() {
        // sshCertificateAuth defaults to off: it cannot work until every managed system has
        // been told to trust the authority, which needs root on each of them.
        assertFalse(SshCertificateAuth.isEnabled());
    }
}
