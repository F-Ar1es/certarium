# Executable specification: Linux installation packages

- Status: approved under standing project-owner authorization on 2026-08-03
- Risk tier: 3 (privileged installation, service account, durable CA keys, upgrades)
- Targets: x86_64 CentOS 7 RPM and Debian-compatible DEB
- Runtime payload: Certarium service plus pinned Tongsuo 8.4.0; no Nginx

## Package scenarios

1. A reproducible build emits one RPM, one DEB, SHA-256 checksums, a build
   manifest, and complete project/Tongsuo license notices.
2. The Go service is a static x86_64 binary. Tongsuo is built in CentOS 7 and
   does not require a glibc symbol newer than 2.17.
3. Installation creates an unprivileged `certarium` system user and group,
   `/var/lib/certarium` mode 0700 owned by that account, and a loopback-only
   systemd service.
4. The service invokes only the packaged pinned Tongsuo executable and starts
   with an explicit crypto timeout and data directory.
5. Installation and upgrade never overwrite or regenerate an existing CA,
   database, issued certificate, CRL, private key, or operator-edited config.
6. Removal stops/removes the service and executable payload but preserves
   `/var/lib/certarium` and `/etc/certarium`; purge is a separate explicit action.
7. RPM and DEB installation in clean target containers starts the service and
   passes `/api/v1/health`, CA initialization, RSA issuance, TLCP issuance, CRL,
   and OCSP smoke tests.
8. Package metadata identifies AGPL-3.0-only for original code, includes the
   commercial-license notice, and retains Tongsuo's Apache-2.0 license.

## Filesystem contract

- `/usr/bin/certarium`: static service binary.
- `/opt/certarium/bin/openssl`: pinned Tongsuo executable.
- `/opt/certarium/lib/`: required Tongsuo runtime modules, if any.
- `/etc/certarium/certarium.env`: non-secret operator configuration, preserved
  across upgrades.
- `/usr/lib/systemd/system/certarium.service`: hardened loopback-only unit.
- `/usr/share/doc/certarium/`: license, notice, third-party notice, build manifest.
- `/var/lib/certarium`: package-owned parent and runtime PKI state; never packaged
  with generated contents.

## Security constraints

- No generated key, CA state, sample password, token, or certificate is present
  in package payloads.
- The service runs with `User=certarium`, `Group=certarium`, `UMask=0077`,
  `NoNewPrivileges=true`, a private temporary directory, and write access only
  to its state directory.
- The packaged listener is `127.0.0.1:8080`. Editing configuration cannot enable
  non-loopback service operation until application authentication exists.
- Maintainer scripts use explicit paths, are idempotent, and do not delete the
  state directory during ordinary uninstall.
- Packages do not execute network downloads during installation.

## Required evidence

- Payload tests inspect ownership, modes, service arguments, licenses, architecture,
  dynamic dependencies, and glibc version references.
- Clean-install and upgrade tests run in CentOS 7 and Debian containers with a
  service-manager substitute when systemd is not PID 1.
- Uninstall tests prove CA/private-key bytes remain unchanged.
- Manual mutants cover root service execution, wildcard listener, state deletion,
  missing Tongsuo license, and a glibc baseline newer than 2.17.
- Final artifact hashes and source commits are recorded in an evidence report.
