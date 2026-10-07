# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [6.0.0]

### Security

- **High: SSH sessions never verified host keys.** Every connection was opened with `StrictHostKeyChecking=no`, which does not mean "warn" — the key a host presents was never compared to anything. A bastion is the worst place for that: it hands the host the application private key, and on an authentication fallback the user's own password or key passphrase, so anything that could answer on a managed system's address once could collect credentials for it. Host keys are now verified against a new `host_key` table, with the mode set by `hostKeyVerification`: `accept-new` (default) records a key on first sight and refuses the connection if it ever changes, `strict` additionally requires a manager to approve each new host key, and `off` restores the old behavior.
- **Request parameters could rewrite the application SSH public key shown to every user.** `BaseKontroller` bound parameters into static fields, and `UserSettingsKtrl` holds the application public key in a static `@Model` field — so `?publicKey=...` rewrote the key displayed on the page that tells users to install it in their `authorized_keys`, for everyone. `?themeMap['x']=y` likewise grew a shared map without bound. Reachable by any authenticated user. The binder now refuses static fields and the palettes are unmodifiable.
- **Any third-party page could end every signed-in user's session.** `CSRFFilter` invalidated the session on a token mismatch, an absent token failed identically, and the filter covers page GETs — so `<img src="https://host/admin/menu.html">` on an unrelated site logged out whoever loaded it. No token knowledge and nothing forged. The request is still refused; the session now survives being targeted.
- **The user list could be sorted by its password column.** `SortedSet` filtered characters rather than column names and the result was concatenated into `order by`, so `?sortedSet.orderByField=password` leaked the relative order of every stored hash, with no quoting or metacharacter needed. Each query now declares its sortable columns and an unrecognized field drops the clause.
- **Fabricated "Authentication Success" records could be written to the login audit log.** The log is one record per line, assembled from the submitted username, which needs no credentials to set — a newline in it appended records of the attacker's choosing. `AuditLogUtil.safe` now strips control characters and caps field length.
- **A downloaded private key could be unencrypted while the UI said otherwise.** `rewrapWithOpenSSHKeygen` discarded `ssh-keygen`'s exit status and returned the temp file regardless; on failure `ssh-keygen` leaves that file untouched, so the method returned the plaintext PEM it was handed. It now checks the exit status and verifies the result really is encrypted by reading the `openssh-key-v1` cipher name, drains output before waiting, closes the child's stdin, and applies a timeout.
- **A key name could inject HTTP response headers.** Key names are user-supplied and went into `Content-Disposition` unescaped on both the private key and certificate downloads. Both now derive the filename through one sanitizer.
- **`authorized_keys` was rewritten through a shell command.** `addPubKey` built `echo '<keys>' > file` and interpolated the host's existing file contents unvalidated, so an apostrophe already in that file — legal, and common in a key comment — closed the quoting. Replaced with SFTP: no shell on either end, so the bug class is gone rather than filtered.
- **The login throttle could be filled with junk to disable it.** `getClientIPAddress` used the whole forwarded-for header as the throttle key, but each hop appends to it, so a client-varied prefix made every request its own entry. It now takes the first address and requires it to parse as an IP literal, and the map is bounded, sweeping expired windows and evicting the oldest in one guarded batch.
- **Removed `X-XSS-Protection`.** It drove the XSS Auditor, which Chrome and Edge removed and Firefox and Safari never shipped, and while live `1; mode=block` was itself usable to disable scripts selectively and to leak cross-site information. HSTS moves to `SecurityHeadersFilter`, where `max-age`, `includeSubDomains` and `preload` are configurable — the latter two off by default, because a browser that cached them refuses plain HTTP to those names for the whole max-age.
- Public key lookups behind the download endpoints now scope ownership in SQL rather than after the fact, and certificate serial numbers fail loudly instead of restarting at 1 when the authority row is missing.
- **Two documented environment variables were silently ignored.** The camelCase-to-`SCREAMING_SNAKE_CASE` conversion keeps a run of capitals glued to the word after it, so `defaultSSHPassphrase` resolved only as `DEFAULT_SSHPASSPHRASE` and `resetApplicationSSHKey` only as `RESET_APPLICATION_SSHKEY` — while the README told operators to export `DEFAULT_SSH_PASSPHRASE` and `RESET_APPLICATION_SSH_KEY`. Anyone following the documentation had their SSH key passphrase quietly read from the properties file instead, and their key reset quietly not happen. Both spellings are now accepted, for every property.

### Added

- **An SSH certificate authority.** Bastillion can sign short-lived OpenSSH certificates instead of relying solely on distributed `authorized_keys`, enabled with `sshCertificateAuth`. The CA private key is generated on first start and never leaves the database — certificates are built and signed in-process rather than by shelling out to `ssh-keygen -s`.
  - Sessions to managed systems authenticate with a certificate carrying the Bastillion username as its key id, so the target host's own logs name the person behind the connection. Default lifetime 5 minutes (`sshCertificateValiditySeconds`).
  - Users can download a certificate for their own registered key and use their own SSH client directly, no longer only the browser terminal. Default lifetime 8 hours (`sshUserCertificateValiditySeconds`).
  - Host certificates are trusted by registering a host CA, published to the verifier as `@cert-authority`, with revoked keys published as `@revoked`.
  - The CA public key is shown and downloadable from user settings, for installing as `TrustedUserCAKeys` on managed hosts.
  - Each system has a **Test cert** action that opens a throwaway connection with a certificate and reports whether the host accepted it, without touching the system's recorded status.
- **A Host Keys screen**, listing every key Bastillion has seen with its fingerprint and when it was first trusted, with approve, revoke and forget actions, plus a navigation badge counting keys currently blocking connections.
- **`keyManagement`**, replacing the old boolean `keyManagementEnabled` with three modes: `manage` (Bastillion owns `authorized_keys`, as before), `append` (add Bastillion's key and leave everything else on the host alone), and `off` (never write to `authorized_keys` at all, for installs authenticating purely by certificate).
- **An Auth column** on the systems screen, showing whether the host accepted a certificate, a key, or a password on the last connection — read back from what the host actually accepted, not from what was offered.
- A `HOSTKEYFAIL` status distinct from a generic failure, since a refused host key needs a specific human decision rather than looking like a dead port or a bad password.
- Copy-to-clipboard on the public key and CA fields, and a startup warning when a certificate lifetime is long enough to outlive revocation.

### Changed

- `authorized_keys` is written over SFTP via a staged write and a rename, rather than streamed over the top of the existing file. A connection lost part way used to leave a half-written or empty file — and in `manage` mode that file is rewritten unattended on every host by the refresh timer, so losing it took the application key with it and locked everyone out of that host. The host now has either the old file or the new one, and the file always ends with a newline so anything else appending to it starts its own line.
- With certificates enabled, the application key is offered as a second identity behind the certificate. Offering the certificate alone cut off every host that had not had `TrustedUserCAKeys` configured yet — including hosts with the key already in their `authorized_keys` — which stranded the operator, the refresh timer being how Bastillion reaches a host to manage it in the first place. Rollout is now incremental: a host takes the certificate once it trusts the CA and keeps working on its key until then.
- The RSA default key length is 4096 rather than falling back to a short length when `sshKeyLength` is unset or not valid for the key type.

### Fixed

- The certificate download refused every request, `getPublicKey(id)` never having populated the owning user id it was checked against.
- A failure with no message rendered as a literal `Error: null` in the systems screen's dialogs.
- Distributing a user's key no longer reports success when the write was skipped, and the application key being uncertifiable is now stated rather than silently falling back.

### Dependencies

- `com.h2database:h2` 2.4.240 → 2.5.252
- `org.bouncycastle:bcprov-jdk18on` 1.85.2 → 1.86
- `org.apache.commons:commons-lang3` 3.20.0 → 3.21.0
- `org.eclipse.jetty:*` 12.1.12 → 12.1.14
- `org.slf4j:slf4j-api` 2.0.18 → 2.0.20

**Upgrade note:** the new tables and columns are created on first start and need no action — upgrading from 5.2.x has been tested end to end. Host key verification defaults to `accept-new`, so existing systems keep connecting and their keys are recorded as they are first seen; set `hostKeyVerification=strict` to require approval instead, or `off` to keep the pre-6.0.0 behavior. The certificate authority is off until `sshCertificateAuth` is set. `keyManagementEnabled=true`/`false` is still honored and maps to `manage`/`append`.

**Upgrading from v4:** v4 kept its H2 database inside the Jetty webapp, encrypted with that install's keystore, so 6.0.0 cannot read it in place. Use the migration tool in [`tools/migrate`](tools/migrate/README.md), which exports every table from the old database (decrypting with the old keystore) and imports it into a new one (re-encrypting with the new keystore) — users keep their existing passwords. Import **straight into 6.0.0**; there is no need to stand up a 5.x install first. Every column a v4 export carries still exists in the 6.0.0 schema, and the two columns 6.0.0 adds to those tables take their default or null. `bastillion-migrate-1.0.0.jar` is attached to the [6.0.0 release](https://github.com/Loophole-LLC/Bastillion/releases/tag/v6.0.0), and `migrate.sh` fetches it automatically, verifying its checksum.

## [5.2.1]

### Security

- **High: SAML/LDAP login permanently deleted other users' SSH keys.** Profile-sync on every SAML/LDAP login ran an unscoped `DELETE FROM user_map WHERE profile_id=?`, wiping every other user's profile membership for that profile instead of just the logging-in user's. The subsequent `deleteUnassignedKeysByProfile()` cleanup then treated those users as unassigned and permanently deleted their registered SSH public keys, with no automatic recovery. Any authenticated SAML/LDAP login — even one with a low-privilege IdP role — could lock every other user (including admins) out of their assigned systems and destroy their keys. `UserProfileDB.assignProfilesToUser()` and `assignProfileToUser()` now scope both deletes to `profile_id=? and user_id=?`. Reported by @tonghuaroot (GHSA-577v-6px6-m424).

### Dependencies

- `com.github.mwiede:jsch` 2.28.6 → 2.28.7
- `github/codeql-action` 4.37.7 → 4.37.9
- `actions/setup-java` 5 → 6

**Upgrade note:** Critical for any deployment using SAML or LDAP authentication — upgrade immediately. Profile assignments for affected users re-sync automatically on their next login, but deleted SSH keys do not come back on their own; a manager must manually re-register them.

## [5.2.0]

### Security

- **Critical: unauthenticated admin bypass.** Route and role checks matched on the raw request URI with a substring `contains()` instead of the container-normalized servlet path. A crafted URI like `/x;/manage/viewUsers.ktrl` could reach any `/manage/*` or `/admin/*` controller — including full account creation — with zero authentication. Now matched on `getServletPath()` with an exact match.
- **SSH terminal WebSocket had no real auth gate.** The `/admin/terms.ws` upgrade request bypasses the servlet-container `AuthFilter` entirely; it was only "failing safe" by accident, via an uncaught NPE. `SecureShellWS.onOpen` now explicitly validates a live admin auth token before allowing the connection.
- **Added login throttling.** Brute-force login attempts were previously unbounded. Now rate-limited per client IP (configurable via `maxLoginAttemptsPerIP` / `loginThrottleWindowMinutes`, default 10 attempts / 5 minutes) rather than per-account, so an attacker can't lock out a known admin by deliberately failing their password.
- **Fixed a file upload path traversal.** `UploadAndPushKtrl.push()` didn't sanitize the uploaded filename before using it to build SFTP push/cleanup paths, allowing a crafted `../../../etc/passwd`-style value to read or delete arbitrary local files.
- **Hardened DB connection handling.** All 12 DAO classes moved to try-with-resources, closing two real connection leaks: one in the terminal output-polling loop (a leak every 25ms on exception) and one on every failed external-auth attempt.

### Added

- **SAML 2.0 SSO**, alongside the existing LDAP/JAAS auth — works with Entra ID, Okta, ADFS, or any SAML 2.0 IdP.
  - Self-signed SP signing/encryption keys generated automatically (no config needed); every outgoing `AuthnRequest` is signed.
  - New `/saml/metadata` endpoint for IdP-side setup via URL import.
  - Optional encrypted-assertion support (`samlWantEncryptedAssertions`).
  - Config is entirely env-var/file driven — no new admin UI, matching the LDAP pattern.
  - SAML role/group claims map onto Bastillion profiles the same way LDAP groups already do.

### Changed

- Modernized UI throughout: new logo/branding (SVG), responsive navbar, consistent button styling across admin and manage views.
- Terminal polish: fixed resizing, cursor/clipboard input, selection clearing after copy, and a duplicate-session output race.
- Fixed zsh sessions leaking `PROMPT_EOL_MARK` markers into terminal/audit output.
- Raised the free system limit.
- Refreshed all product screenshots.
- Upgraded embedded Jetty from 11 (Jakarta EE 9) to 12 (Jakarta EE 10).

### Dependencies

- `xmlsec` 2.2.6 → 4.0.4 (also closes CVE-2023-44483, pinned similarly to the existing `mina-core` pin)
- `jakarta.servlet-api` 6.0.0 → 6.1.0
- `commons-codec` 1.22.0 → 1.22.1
- `com.github.mwiede:jsch` 2.28.4 → 2.28.6
- `org.bouncycastle:bcprov-jdk18on` 1.85 → 1.85.2
- `org.junit.jupiter:junit-jupiter` 6.1.2 → 6.1.3
- `maven-clean-plugin` 3.4.1 → 3.5.0
- `frontend-maven-plugin` 2.0.1 → 2.0.2
- `grunt` 1.6.2 → 1.6.3, `brace-expansion` (npm, transitive)
- `github/codeql-action` 4 → 4.37.7

**Upgrade note:** if you run behind LDAP/JAAS today, this release is a drop-in upgrade — no config changes required. SAML is opt-in via new env vars. Given the auth-bypass and WS-terminal-auth fixes above, upgrading promptly is strongly recommended for all deployments.
