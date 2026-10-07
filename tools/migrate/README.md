# Bastillion v4 H2 database migration tool

Migrates all data (users, systems, profiles, scripts, public keys, audit logs, and the
Bastillion SSH application key/identity) from an old Bastillion H2 database into a new
Bastillion instance's H2 database.

Import straight into 6.x: there is no need to install 5.x first. Every column a v4 export
carries still exists in the 6.x schema, and the columns 6.x adds (`user_theme.ui_theme`,
`system.last_auth_method`) take their default or null, since the importer names the columns
it found in the export.

This is a **standalone Maven project**: it has its own `pom.xml` and isn't a module of
Bastillion's own build, and it doesn't depend on Bastillion's build artifact at all. It
reuses Bastillion's own `AppConfig`/`EncryptionUtil`/`KeyStoreUtil` classes (and the bundled
`BastillionConfig.properties` defaults) via **symlinks** straight into
`src/main/java`/`src/main/resources`, compiled directly into this tool's
own jar. That guarantees the crypto here matches the real app exactly - nothing is
reimplemented - without ever needing `mvn install` in the main repo first, and without
pulling in everything else Bastillion depends on (Jetty, WebSocket, JAAS - none of it is
needed here, so the resulting jar is a fraction of the size of Bastillion's own).

It works in two phases so no secrets ever need to be decrypted and re-encrypted in the same
process/keystore context:

1. **export** - reads every table from the old database and writes it to a JSON file. The
   three app-level-encrypted columns (`users.otp_secret`, `application_key.private_key`,
   `application_key.passphrase`) are decrypted to plaintext using the OLD instance's
   `bastillion.jceks` keystore, via the symlinked `EncryptionUtil`/`AppConfig`/`KeyStoreUtil`.
2. **import** - deletes all rows from the new instance's 12 Bastillion tables (a full
   replace, not a merge) and inserts the migrated rows, re-encrypting those same three
   columns with the NEW instance's own keystore. Auto-increment/identity sequences are
   fixed up afterward so the app can keep inserting normally.

## Prerequisites

- Nothing needs to be built by hand - `migrate.sh` runs `mvn package` here the first time,
  automatically, whenever the jar is missing.
- The **new** instance's database must already exist - i.e. start this Bastillion once against
  the config dir you intend to migrate into, let it finish booting (creates schema,
  `bastillion.jceks`, and a default `admin`/`changeme` user), then stop it (Ctrl+C). The import
  tool intentionally does not create schema itself, to avoid drifting out of sync with
  `DBInitServlet`'s DDL - it only replaces data in an already-initialized DB.

## Finding your old (v4) config directory

`<old-config-dir>` is whatever directory the old instance's `BastillionConfig.properties` and
`bastillion.jceks` live in. For the standard v4 Jetty distribution (`startBastillion.sh` /
`stopBastillion.sh`), that's the exploded webapp's classpath root - same directory the H2
file's `keydb/` sits under - e.g. an install at `/opt/Bastillion-jetty` has it at:
```
/opt/Bastillion-jetty/jetty/bastillion/WEB-INF/classes/
```

## Usage

```bash
# 1. Export the old database (plaintext secrets end up in the output file - see Security below)
cd tools/migrate
./migrate.sh export /opt/Bastillion-jetty/jetty/bastillion/WEB-INF/classes/ ~/bastillion-export.json

# 2. Start the new Bastillion once against the config dir you're migrating into, then stop
#    it (Ctrl+C) once it has finished booting - this creates the schema + jceks + default
#    admin. From the repo root, packaged jar shown here (mvn compile exec:java -DCONFIG_DIR=
#    works the same way for a source checkout):
cd ../..
java -DCONFIG_DIR=/data/bastillion/ -jar target/bastillion-6.0.0.jar

# 3. Import into the new database (full replace of all 12 tables) - <new-config-dir> first,
#    then the export file:
cd tools/migrate
./migrate.sh import /data/bastillion/ ~/bastillion-export.json --yes-replace-all-data

# 4. Delete the export file - it contains decrypted secrets.
rm ~/bastillion-export.json
```

`<config-dir>` (old or new) is whatever directory that instance's `BastillionConfig.properties`
and `bastillion.jceks` live in (same thing you'd pass as `-DCONFIG_DIR`). The H2 file itself may
be at `<config-dir>/keydb/bastillion.mv.db` (the real app's normal layout) or flatly at
`<config-dir>/bastillion.mv.db` - both are auto-detected.

## What gets migrated

All 12 tables: `users, user_theme, system, profiles, system_map, user_map, application_key,
status, scripts, public_keys, session_log, terminal_log`. This includes the Bastillion
application SSH key pair (`application_key`), which is migrated rather than regenerated so
the remote hosts' `authorized_keys` entries (authorized against the old public key) keep
working without any changes on those hosts.

Password hashes and salts are copied as-is (not re-hashed) - Bastillion's `verifyHash()`
supports the newer PBKDF2 format, its own pre-PBKDF2 single-round SHA-256 format, and a real
v4 database's single-round SHA-256 format (v4 concatenates the password and salt into one
string before hashing, rather than digesting them separately), so old users can log in
immediately with their existing passwords.

## Security notes

- The export JSON file contains **decrypted** SSH private key material, the application key
  passphrase, and any users' OTP/2FA seeds. It's written with owner-only file permissions
  (`chmod 600`-equivalent), but treat it as sensitive: keep it off shared/network storage and
  delete it as soon as the import succeeds.
- `import` is destructive to the *target* database: it deletes all existing rows in all 12
  tables before inserting. That's why it requires the explicit `--yes-replace-all-data` flag,
  and prints the row counts it's about to delete first.
