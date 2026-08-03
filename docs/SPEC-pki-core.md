# Executable specification: PKI core

- Status: approved by Carl Flynn on 2026-08-03
- Risk tier: 3 (private keys, durable CA state, concurrency, public API)
- Runtime dependencies added: none; Go standard library only
- External process boundary: pinned Tongsuo executable, invoked without a shell
- Git workflow: `feat/pki-core`, checkpoint commits and pushes at major nodes

## Scenarios

1. Empty-directory initialization creates independent RSA and SM2 CA state,
   initializes serial/CRL metadata, and stores private keys with mode 0600.
2. Reinitialization fails and does not alter existing CA material.
3. RSA issuance accepts validated CN, DNS, IPv4/IPv6 SAN, and bounded validity;
   the resulting certificate has serverAuth EKU and the requested SANs.
4. Invalid SANs, unsafe names, and excessive validity fail without state change.
5. TLCP issuance creates distinct signing and encryption certificates and keys;
   subjects and SANs match while key usages and serials differ.
6. Durable state survives restart and uses temporary-file plus atomic replacement.
7. Concurrent issuance never reuses a serial number.
8. Tongsuo failure or timeout is reported without logging passwords/private keys
   and without publishing a partial successful record.

## Negative constraints

- No path traversal, shell command construction, silent overwrite, private key
  in the Web root, secret-bearing log entry, or default non-loopback listener.
- Existing health/status endpoints remain compatible.
- Generated PKI data and credentials must remain ignored by Git.

## Failure model and required layers

- Partial initialization/write: failure injection and atomic-state tests.
- Serial collision/race: concurrent race-detector test.
- Hostile subject/SAN: table tests plus property/fuzz-style generated inputs.
- Wrong TLCP key reuse/usage: certificate inspection integration tests.
- Tongsuo failure: controlled failing runner and real-process integration test.
- Secret exposure: file-mode assertions and repository/log secret scans.

## Final gauntlet

The persisted `tools/gauntlet.sh` must run tests with race detection and shuffled
order, coverage, build, vet/format, manual mutation, secret/license checks, a
real Tongsuo issuance, and a real HTTP health request. Every skipped layer must
be recorded in `docs/EVIDENCE-pki-core.md` with a reason.
