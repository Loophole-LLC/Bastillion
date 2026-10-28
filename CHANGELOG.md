# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [6.0.3]

### Changed

- **An LDAP or SAML outage no longer looks like a wrong password.** Every failure of the external login - a directory that could not be reached, a `jaas.conf` naming a module that does not exist, an error while signing the user in - used to come back as "Login credentials are invalid", which is how LDAP login stayed broken unnoticed until 6.0.2. Now only a directory or IdP that actually rejects the credentials says so. When the directory cannot be reached, the login page says "The directory could not be reached. Please try again later or contact an administrator", the error log says why, and those attempts do not count against the client's login throttle. SAML redirects back with `ssoError=unavailable` and shows "Single sign-on is unavailable" when its settings cannot be loaded; a malformed SAML response still counts as an invalid login.
- **Local accounts still sign in while the directory is down.** A break-glass local account (such as a Manager kept for that purpose) keeps working during a directory outage; the outage is only reported once no local account matches.
- A database error while signing in an LDAP or SAML user is now reported as an error rather than as invalid credentials.

### Security

- **Controllers accept only the request parameters their forms send.** Every field of every model object used to be settable by name, along with each controller's own internal state, so a form posting `user.firstNm` equally accepted `user.authToken`, and `?errors=` or `?AUTH_ERROR=` could put text of the requester's choosing on a page. Each controller now lists the parameters it accepts, and anything else is ignored. No exploitable case was found; this closes off the class of bug that let `?publicKey=` replace the key shown on the Settings page, rather than fixing a specific new one. If you have customised the web UI with extra form fields, they need adding to the controller's `@Model(params = ...)` list.
- **Disabling a key now takes it off every system.** The confirmation says a disabled key "is removed from every system", but only the record clicked was disabled. Any other record of the same key - registered under another profile, for all systems, or by another user - stayed enabled and kept the key in those hosts' `authorized_keys`. Disabling and enabling now apply to every record with that key's fingerprint, and every system is refreshed.
- **A key can no longer be registered twice in the same place.** The check for "already registered under the selected profile" never matched a new key, nor any key for all systems, so the same key could be added again - and, with the problem above, survive being disabled.
- **Pasted public keys must be a plain key.** Anything containing `ssh-` was accepted: `ssh-ed25519 x`, a key labelled with the wrong type, or a key with `authorized_keys` options such as `command="..."` in front, which were stored and pushed to hosts exactly as typed. A key must now be `<type> <base64 key> [comment]`, with the key matching its type. Keys already saved are unaffected. The same check applies to host certificate authorities.

### Added

- **A startup warning when LDAP cannot work.** If `jaasModule` is set but `jaas.conf` cannot be read, has no entry by that name, or names a login module that does not exist, Bastillion prints "WARNING: LDAP login will fail: …" to the console and the error log.

### Fixed

- **Terminal colors and color themes are saved again.** Since 6.0.0, choosing them under Settings appeared to save but stored nothing, so terminals kept the default colors.
- **Opening a terminal prompts for a password or key passphrase again.** Since 4.0.0, connecting to a host that needed a password (the application key not yet installed) or an application key passphrase showed a bare "Failed" error instead of the prompt the terminal screen asks for. Both prompts now appear, and registering a system shows "Passphrase" rather than "Failed" when the application key's passphrase is missing or wrong.
- **Two key refreshes reaching one host at once could delete its `authorized_keys`.** Since 6.0.0, writes stage the new file and rename it into place, but every write used the same staged name, so one could rename another's file away and then remove the original with nothing to replace it - leaving the host with no `authorized_keys` at all, Bastillion's own key included, until it was fixed by hand. Disabling a key, assigning a profile and the refresh timer each start their own refresh, so this needed nothing unusual. Each write now has its own staged file, writes to the same file run one at a time, and the original is only removed once its replacement is known to exist.
- The Manage Systems page showed a red "Certificate not accepted" banner on every visit since 6.0.0, without any certificate test having been run. It now appears only after one.
- The "Replace application SSH key" section of Settings opened expanded on every visit; it now starts collapsed. A missing certificate authority now shows its explanation instead of an empty key.
- Adding a user accepted any user type or authentication type. A type other than "Administrative Only" or "Full Access" gave the user no access at all while the user list showed "Full Access"; both are now validated.
- Downloading a generated private key without its name returned an error page; it now returns nothing.
- The application public key and certificate authority key on the Settings page were read from the database once, shortly after startup, so a failure at that moment left them blank until a restart. They are now read on every request.

### Internal

- `@Model(params = {...})` lists the request parameters a controller field accepts; a field without it is output only. The names are checked at startup, and a test fails the build if a template sends a parameter no controller accepts.
- SSH connections are now tested end to end against an in-process SSH/SFTP server (Apache MINA SSHD, test scope only): password and key login, installing the application key over SFTP, host key trust and refusal, terminal output, certificate tests, and how each failure is reported.
- Startup (`DBInitServlet`) is split into named steps, unchanged in order and output, and no longer leaks its database connection if a step fails.
- Line endings are LF throughout, pinned by `.gitattributes`; `.git-blame-ignore-revs` lets blame skip the conversion commit.
- OpenSSH key encoding moves from `SSHUtil` to `OpenSSHKeyUtil`, and `authorized_keys` handling to `AuthorizedKeysUtil`, unchanged. Log lines from that code now appear under those class names.

**Upgrade note:** no config or schema changes. If you use LDAP, check the console after upgrading for a "LDAP login will fail" warning, which means `jaas.conf` needs fixing before directory users can sign in.

## [6.0.2]

Not released separately: these changes first shipped in 6.0.3.

### Fixed

- **LDAP/JAAS login failed for everyone, on every release since 4.0.0.** The directory accepted the password, then `ExternalAuthUtil` threw while reading what it had returned, and the catch-all logged an error and treated it as a failed login. Two causes: it read `LoginContext`'s private fields by reflection, which Java 17+ refuses without `--add-opens`, so every JAAS module failed, including the shipped `ldap-ol` and `ldap-ad` examples; and for Jetty's `LdapLoginModule` it asked for a user `attributes` field on a class that has not had one since Jetty 10. It now uses only public JAAS and Jetty API, and runs the `jaas.conf` examples against an in-memory directory in its tests.
- **The shipped `jaas.conf` role-mapping example could not load.** `ldap-ol-with-roles` named `org.eclipse.jetty.jaas.spi.LdapLoginModule`, which no longer exists in Jetty 12. It now names `org.eclipse.jetty.security.jaas.spi.LdapLoginModule`, and the old name is mapped in code, so a `jaas.conf` copied from an earlier release keeps working unedited.
- **LDAP roles could put a user in the wrong profile.** Role names were matched to profiles with `LIKE`, so an `_` in a role acted as a wildcard: a user with the role `web_prod` was added to the `web-prod` profile and could reach its systems. Role names now match profile names exactly (still ignoring case).
- **Session audit filters showed other users' sessions.** Filtering by user or system used `LIKE`, so filtering on `j_doe` also listed `jxdoe`'s sessions. Filters now match the selected name exactly.

### Added

- **`externalAuthLinkBasicAccounts`**, controlling whether an LDAP or SAML login may sign in to an existing Basic (local-password) account with the same username. `true` (default) keeps the current behavior: the accounts are linked and the local password is cleared. `false` refuses the login and logs it, so a directory or IdP identity named `admin` cannot take over the bootstrap account; switch an account to **External** under **Manage → Users** to let it sign in externally.
- **Schema versioning.** The database now records its schema version in a `schema_version` table, and changes are applied as numbered migrations on startup, each printed as it runs. An existing database is brought up to date and recorded at version 4 on its first start; nothing about its data changes.

### Changed

- LDAP and SAML now share one implementation for matching a login to an account, creating it if needed, syncing profiles and issuing the session token. New external accounts are created with their external auth type directly, rather than as Basic and switched immediately after.
- Remaining exact-value lookups (auth tokens, user ids, key fingerprints, status codes) use `=` instead of `LIKE`, and the build now fails on any `LIKE` not marked as an intentional search.
- Loaded user records no longer carry the password hash and salt, so the user list's page model no longer contains them.

**Upgrade note:** upgrade promptly if you use LDAP — no LDAP user has been able to sign in since 4.0.0, and this release fixes that without any change to `jaas.conf`. If a user's roles map to profiles, check their memberships after their first login: matching is now exact, so a role that only matched a profile through an `_` wildcard no longer does. No other config changes are needed. On first start, the console prints `Applied database migration 1` through `4`; that is the existing schema being recorded, and later restarts print nothing.

## [6.0.1]

### Security

- **High: SAML/LDAP login could sign in as a different user.** `AuthDB.getUserByUID` matched the SAML NameID or LDAP login name with `lower(username) like lower(?)`, so `%` and `_` in it acted as wildcards, and when several accounts matched, the last row won. An IdP identity such as `john_smith@corp.com` signed in as `john.smith@corp.com`, up to Full Access. Logging in also rotated the victim's auth token, logging them out, cleared their local password, and on SAML rewrote their profile membership from the attacker's role claims. The lookup is now an exact case-insensitive match, and a login that matches more than one account is refused. `UserDB.isUnique` had the same `LIKE` and wrongly reported usernames containing `_` as taken; it now matches exactly too. Reported by @a25370 (GHSA-5qgc-52c7-26mg).

### Changed

- The README now recommends locking down the default `admin` account: change its password, require two-factor, and delete it on LDAP/SAML deployments once a directory user has Full Access, since an external identity named exactly `admin` would sign in as it.

### Dependencies

- `com.github.mwiede:jsch` 2.28.7 → 2.28.8
- `org.apache.mina:mina-core` 2.2.9 → 2.2.10
- `commons-codec:commons-codec` 1.22.1 → 1.23.0
- `github/codeql-action` 4.38.2 → 4.39.0

**Upgrade note:** upgrade promptly if you use SAML or LDAP login; local-only installs are not affected by the login issue. No config or schema changes. A local account that was matched this way had its password cleared, so a user whose local password suddenly stopped working is worth checking.

## [6.0.0]

### Security

- **High: SSH sessions never verified host keys.** Every connection was opened with `StrictHostKeyChecking=no`, which does not mean "warn" — the key a host presents was never compared to anything. A bastion is the worst place for that: it hands the host the application private key, and on an authentication fallback the user's own password or key passphrase, so anything that could answer on a managed system's address once could collect credentials for it. Host keys are now verified against a new `host_key` table, with the mode set by `hostKeyVerification`: `accept-new` (default) records a key on first sight and refuses the connection if it ever changes, `strict` additionally requires a manager to approve each new host key, and `off` restores the old behavior.
- **Request parameters could rewrite the application SSH public key shown to every user.** `BaseKontroller` bound parameters into static fields, and `UserSettingsKtrl` holds the application public key in a static `@Model` field — so `?publicKey=...` rewrote the key displayed on the page that tells users to install it in their `authorized_keys`, for everyone. `?themeMap['x']=y` likewise grew a shared map without bound. Reachable by any authenticated user. The binder now refuses static fields and the palettes are unmodifiable. Also reported independently by @a25370 (GHSA-w4w8-68r7-vmvv).
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
