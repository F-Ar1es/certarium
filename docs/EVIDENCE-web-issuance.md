# Local Web issuance verification evidence

- Verification date: 2026-08-03 (Asia/Shanghai)
- Source branch: `feat/pki-core`
- Environment: Apple Container, Linux arm64, Go 1.22
- Crypto: pinned Tongsuo 8.4.0 (`a8ae0925d26de3b449f7a21767910cd41291bcd8`)
- Result: **passed**

## Proved behavior

- The service rejects non-loopback listeners.
- Fresh status, one-time RSA/SM2 CA initialization, RSA issuance, TLCP paired
  issuance, inventory, and private-key download completed through real HTTP calls.
- Unknown JSON fields, oversized/invalid mutation input, missing explicit
  server-key confirmation, and internal error leakage are rejected.
- Download names are constrained by a per-bundle manifest. CA keys, paths, CSRs,
  configuration files, temporary files, and symlinks are not downloadable.
- Leaf private-key downloads use attachment disposition and `Cache-Control: no-store`.
- The UI uses no external CDN/framework and renders dynamic certificate values
  with DOM text nodes rather than HTML parsing.
- Existing PKI race, property, real-crypto, license, dependency, secret, build,
  and HTTP health layers remain green.

## Mutation evidence

Five PKI mutants and five Web/API mutants were killed. The Web mutants removed:

1. Explicit server-side private-key confirmation.
2. Loopback-only listener enforcement.
3. The download manifest allowlist.
4. Download symlink rejection.
5. Safe DOM text rendering.

The final persisted command was `tools/gauntlet.sh`; it ended with
`WEB SMOKE PASSED` and `GAUNTLET PASSED`.

## Current boundary

This checkpoint is a local single-operator issuance MVP. Authentication,
non-loopback administration, revocation, CRL, OCSP, packaging installation, and
HSM integration remain outside this evidence claim.
