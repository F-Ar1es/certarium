# Certarium

[![Release](https://img.shields.io/github/v/release/F-Ar1es/certarium)](https://github.com/F-Ar1es/certarium/releases/latest)
[![CI](https://github.com/F-Ar1es/certarium/actions/workflows/ci.yml/badge.svg)](https://github.com/F-Ar1es/certarium/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![AI-assisted: OpenAI Codex](https://img.shields.io/badge/AI--assisted-OpenAI%20Codex-000000.svg)](AI_ASSISTED_DEVELOPMENT.md)

[简体中文](README-zh.md) · [Documentation](docs/PRODUCT.md) · [Releases](https://github.com/F-Ar1es/certarium/releases)

Certarium is a self-hosted certificate laboratory for development and
interoperability testing. It was created to reduce the repeated CA setup and
manual certificate work required when company products need standard TLS or
Chinese commercial cryptography/TLCP certificates for testing.

It is a certificate-issuance and lifecycle workbench—not a TLS terminator,
reverse proxy, load balancer, or public-trust CA.

## Why Certarium?

Testing TLS and TLCP commonly means rebuilding CA databases, OpenSSL/Tongsuo
configuration, certificate profiles, dual-certificate pairs, CRLs, and OCSP
responders. Certarium packages those tasks behind one local Web UI and API so
developers and test engineers can spend their time testing the product instead
of rebuilding a disposable PKI.

## Features

- initialize independent private RSA and SM2 root CAs;
- issue RSA server certificates for standard TLS;
- issue matched SM2 signing and encryption certificate pairs for TLCP;
- add DNS, IPv4, and IPv6 Subject Alternative Names;
- inspect certificate serials, purpose, SANs, validity, and state;
- download individual files or a complete certificate bundle;
- revoke certificates and publish RSA/SM2 CRLs;
- answer standard OCSP requests with good, revoked, or unknown status;
- protect CA keys with AES-256 encrypted key files;
- append security-relevant actions to a local JSONL audit log;
- create and restore encrypted offline backups;
- provide a loopback-only Web UI and automation API.

## Supported release targets

Certarium v0.1.0 ships self-contained **x86_64** packages containing the service
and pinned **Tongsuo 8.4.0** runtime:

| System | Package |
| --- | --- |
| CentOS 7-compatible RPM systems | `certarium-0.1.0-1.el7.x86_64.rpm` |
| Debian-compatible systems | `certarium_0.1.0-1_amd64.deb` |

ARM64 packages and real-HSM/PKCS#11 integration are not part of v0.1.

## Quick start

Download a package from the [v0.1.0 release](https://github.com/F-Ar1es/certarium/releases/tag/v0.1.0),
then install it:

```sh
# CentOS 7-compatible system
sudo yum install ./certarium-0.1.0-1.el7.x86_64.rpm

# Debian-compatible system
sudo apt install ./certarium_0.1.0-1_amd64.deb
```

Start the service:

```sh
sudo systemctl enable --now certarium
curl http://127.0.0.1:8080/api/v1/health
```

Certarium deliberately listens only on `127.0.0.1:8080`. From another machine,
open an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 user@certarium-host
```

Then open <http://127.0.0.1:8080> and:

1. initialize the lab CA with your organization name;
2. download and trust the RSA or SM2 root only on intended test clients;
3. issue an RSA certificate or TLCP signing/encryption pair;
4. enter every DNS name and IP address the client will use;
5. explicitly confirm server-side private-key generation;
6. download the files or complete bundle and protect all private keys.

## Backup and recovery

Use a separate mode-0400 password file. Stop the service for a consistent
offline snapshot:

```sh
sudo systemctl stop certarium
sudo certarium-backup -mode backup \
  -data-dir /var/lib/certarium \
  -config-dir /etc/certarium \
  -file /secure/certarium.backup \
  -passphrase-file /secure/backup.pass
sudo systemctl start certarium
```

See [Backup and restore](docs/BACKUP-RESTORE.md) before using `-replace`.

## Security and product boundary

Certarium is for isolated development and interoperability labs. The Web/API
has no user authentication because it is loopback-only. Do not expose it
directly to a LAN or the Internet, and do not use its roots as public trust
anchors.

Not included in v0.1:

- TLS/TLCP traffic termination or certificate offload;
- reverse proxying, load balancing, health checks, or HA;
- public CA operation, multi-tenancy, authentication, or RBAC;
- production HSM/PKCS#11 key custody;
- ARM64 release packages.

Read [Security model](docs/SECURITY.md), [Installation](docs/INSTALL.md), and
[Operations](docs/OPERATIONS.md) before broader testing.

## Build and verification

Apple Silicon with Apple Container:

```sh
./scripts/build-packages-apple-container.sh
./scripts/test-install-packages-apple-container.sh
```

x86_64 Linux with Docker:

```sh
./scripts/build-packages-linux.sh
./scripts/test-install-packages-linux.sh
```

The project uses the old-coder evidence-first workflow. The executable release
specification and results are in [SPEC-v0.1-release.md](docs/SPEC-v0.1-release.md)
and [EVIDENCE-v0.1.md](docs/EVIDENCE-v0.1.md).

## Human direction and Codex assistance

The product concept, scope, acceptance decisions, and releases are directed by
**Carl Flynn**. OpenAI Codex assists with implementation, tests, documentation,
research, and verification. Codex is a development tool, not a copyright owner,
maintainer, or release decision-maker. See
[AI-assisted development](AI_ASSISTED_DEVELOPMENT.md).

Repository-specific instructions for Codex and compatible coding agents live in
[AGENTS.md](AGENTS.md). This follows Codex's documented repository-instruction
mechanism rather than embedding an AI service in the application.

## License

Original Certarium code is licensed under `AGPL-3.0-only`. A separate commercial
license is available for organizations that cannot use the AGPL; see
[COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). Third-party components retain
their own licenses as listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
