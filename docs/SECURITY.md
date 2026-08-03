# Security model

Certarium is a single-operator private PKI workbench for labs. It is not a
public-trust CA, production multi-tenant CA, TLS terminator, or HSM service.

- The unauthenticated Web/API listener is loopback-only. Remote use requires an
  operator-controlled tunnel; direct LAN exposure is unsupported.
- RSA and SM2 CA keys are AES-256 encrypted. The credential comes from a strict
  regular file and reaches Tongsuo through a replaced child environment, not argv.
- Leaf keys are plaintext mode 0600 only after explicit server-generation consent.
- Required operations append fsynced JSONL audit records without bodies, keys,
  or passphrases. An unavailable audit destination blocks mutations.
- Backups are encrypted and authenticated; password loss is unrecoverable.
- HSM/PKCS#11, authentication/RBAC, HA, multi-tenancy, ARM64 packages, and
  external exposure are outside v0.1.
