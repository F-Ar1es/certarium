# Executable specification: Certarium v0.1 release closure

- Status: approved under the project owner's standing autonomous authorization
  on 2026-08-03
- Risk tier: 3 (durable CA secrets, privileged packaging, backup/restore, public release)
- Dependencies: Go standard library and the already pinned Tongsuo 8.4.0 only;
  GitHub Actions uses pinned major official actions. No new application library
  is authorized or required.

## Failure model

1. A mutation succeeds without an audit record, or an attacker injects newlines
   into a record. Catch with handler tests, JSON-lines parsing, concurrency tests,
   size limits, and audit mutants.
2. An audit record leaks a passphrase, private key, request body, or certificate
   key bytes. Catch with secret-canary tests and committed/runtime secret scans.
3. CA keys remain plaintext, a passphrase is accepted from argv/environment, or
   the service starts with a missing/world-readable credential. Catch with real
   Tongsuo inspection, CLI tests, package contract tests, and permission mutants.
4. Encrypted CA keys make CRL, OCSP, issuance, or restart unusable. Catch by
   running the complete RSA/TLCP/CRL/OCSP smoke twice against the same state.
5. Backup is partial, plaintext, silently corrupt, path-traversing, or restore
   overwrites live state after a failed validation. Catch with encrypted archive
   inspection, corruption/wrong-password/path traversal tests, and restore rollback.
6. Upgrade or uninstall destroys credentials, audit logs, CA state, or operator
   configuration. Catch with package install/upgrade/remove hash comparisons.
7. CI or release artifacts differ from locally tested inputs. Catch with one
   version source, checksums, artifact inspection, and a release workflow that
   consumes the same packaging scripts.

## Audit scenarios

1. Every initialize, RSA/TLCP issue, certificate-file download, and revoke attempt
   appends one newline-terminated JSON object to `/var/lib/certarium/audit.jsonl`.
2. Each object has UTC timestamp, request ID, remote address, action, resource,
   outcome (`success` or `failure`), and stable error code where applicable.
3. Concurrent requests produce complete independently parseable records; restart
   appends without truncating prior records; file mode is 0600.
4. Audit data never contains request bodies, CA passphrases, PEM private-key data,
   or response bodies. Failure to write a required audit record fails the mutation
   closed with an internal error.

## Encrypted CA-key scenarios

1. Startup requires `-ca-passphrase-file`; it rejects symlinks, empty files,
   values over 1024 bytes, and any file with group/other permission bits.
2. The passphrase is read into memory, passed only through a child-process
   environment variable, removed from inherited environment, and never placed in
   command arguments or logs.
3. First initialization writes AES-256-encrypted RSA and SM2 root keys. Tongsuo
   cannot read them without the passphrase and can read them with it.
4. Issuance, CRL, OCSP, revoke, process restart, and package smoke work using the
   encrypted root keys. Explicitly requested downloadable leaf/server keys remain
   unencrypted because the caller requested server-side key generation.
5. Installation creates a random 256-bit credential only when absent, owned by
   `certarium`, mode 0400. Upgrade, removal, and reinstall preserve it.

## Backup and restore scenarios

1. An offline backup command creates a single AES-256 encrypted artifact from
   configuration, passphrase credential, PKI state, and audit log; no plaintext
   temporary archive remains after success or failure.
2. A manifest records format version, creation time, and SHA-256 hashes for every
   regular file. Restore rejects wrong passwords, corruption, absolute/parent
   paths, links, devices, missing files, and hash mismatches.
3. Restore targets an empty data/config destination by default. Replacing an
   existing installation requires an explicit flag, first preserves the old state,
   and rolls it back if validation or publication fails.
4. A real round trip proves certificate inventory, both CA private-key hashes,
   audit history, issuance after restore, CRL, and OCSP remain valid.

## Packaging and system scenarios

1. RPM and DEB contain the credential bootstrap, audit path, backup/restore tool,
   hardened loopback service, licenses, and pinned Tongsuo.
2. Clean install, same-version reinstall/upgrade, restart, and ordinary removal
   preserve all durable state and pass the complete package smoke.
3. A systemd-nspawn or VM test boots systemd as PID 1, installs the package,
   verifies enabled/active state and journal output, reboots, and verifies health
   and existing inventory. If this host cannot provide nested virtualization or
   systemd PID 1, the runnable test is delivered and evidence marks execution as
   unavailable rather than passed.

## CI, documentation, and release scenarios

1. Pull requests run formatting, vet, race/randomized tests, mutation tests,
   secret/license checks, and the Web/API smoke.
2. Tags matching `v*` build the same RPM/DEB pipeline, verify package smokes,
   publish SHA-256 checksums, and attach artifacts to a GitHub Release.
3. Product, security, installation, upgrade, backup/restore, CA-import, and
   troubleshooting documentation agree with the shipped single-package design.
4. Release `v0.1.0` is created only after the final gauntlet and package hashes
   are recorded in evidence. It is not described as production/public-trust PKI.

## Invariants

- The listener remains loopback-only and unauthenticated remote administration
  remains impossible.
- No generated CA, password, token, key, certificate database, backup, or runtime
  audit file is committed or embedded in packages.
- Existing public API routes and response fields remain compatible.
- Nginx/TLCP termination, HA, load balancing, HSM, multi-tenancy, and ARM64 remain
  out of v0.1 scope.

## Gauntlet and checkpoint plan

- Persist new tests and manual mutants before implementation and observe RED.
- Commit/push after audit, encrypted-key/backup, packaging/CI, and evidence stages.
- Run format, vet, race/shuffle, changed-behavior coverage, manual mutation,
  adversarial filesystem tests, real Tongsuo execution, package install/upgrade/
  remove, license/dependency/secret checks, and a complete fresh final run.
- Record any unavailable systemd-VM layer explicitly in final evidence.
