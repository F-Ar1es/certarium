# Certarium v0.1 scope

## User outcome

An operator installs one package, initializes a lab PKI, opens a Web page, and
issues downloadable standard or GM certificates without manually maintaining
OpenSSL configuration and CA database files.

## v0.1 acceptance criteria

1. Runs on x86_64 CentOS 7 and newer mainstream RPM/DEB systems.
2. First-run initialization creates independent RSA and SM2 lab roots.
3. Issues RSA server certificates with DNS/IP SANs.
4. Issues matched TLCP signing and encryption certificates.
5. Never returns a private key unless the user explicitly chose server-side key generation.
6. Lists certificate serial, subject, SANs, purpose, validity, and state.
7. Revokes an issued certificate and publishes a refreshed CRL.
8. Provides an OCSP URL and reports good/revoked/unknown from the CA database.
9. Web and API actions are auditable and reject unsafe names and SAN values.

## Trust and security boundary

This is an experimental private PKI, not a public trust service. The service
runs as an unprivileged account. CA keys live outside the Web root with mode
0600. The initial release supports encrypted file keys; PKCS#11/HSM support is
a later extension point.

## Packaging

- `certarium`: static service binary, UI assets, service unit, and defaults.
- `certarium-tongsuo`: pinned Tongsuo CLI/runtime built for the target baseline.
- runtime state: `/var/lib/certarium` (created during initialization, never packaged).
- configuration: `/etc/certarium`.
- logs: system journal plus `/var/log/certarium` where file logs are required.
