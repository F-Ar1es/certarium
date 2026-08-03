# Executable specification: local Web issuance MVP

- Status: approved by standing project-owner authorization on 2026-08-03
- Risk tier: 3 (CA initialization, server-generated private keys, public HTTP API)
- Runtime dependencies proposed: none; Go standard library and pinned Tongsuo only
- Default trust boundary: loopback-only HTTP service for a single lab operator
- Out of scope for this increment: revocation, CRL, OCSP, authentication,
  non-loopback administration, HSM/PKCS#11, and multi-user operation

## User-visible scenarios

1. A fresh local installation shows an initialization page and does not create
   CA material until the operator submits a validated organization name.
2. Initialization creates independent RSA and SM2 roots once. A repeated request
   returns a conflict and does not modify either root.
3. The dashboard reports initialized/uninitialized state without exposing the
   filesystem data directory or any key path.
4. An operator can request an RSA server certificate using a safe bundle name,
   common name, DNS/IP SANs, and validity from 1 through 825 days.
5. An operator can request a TLCP pair with the same validated identity data;
   the resulting signing and encryption certificates retain distinct keys,
   serials, and usages.
6. Server-side private-key generation requires a separate explicit confirmation
   in both Web and API requests. An omitted or false confirmation is rejected.
7. A successful issuance response contains metadata and opaque download IDs,
   never PEM private-key contents, absolute paths, or command output.
8. The operator can list issued bundles and download public certificates. The
   corresponding leaf private key is downloadable only through its explicit
   private-key endpoint and is served as an attachment with `no-store` headers.
9. RSA and TLCP downloads use predictable archive contents and safe filenames;
   CA private keys are never addressable by any route. Root public certificates
   have separate public-download routes.
10. Every mutation records timestamp, action, safe bundle identifier, outcome,
    and remote loopback address without recording subjects containing unsafe
    control characters, private-key data, secrets, or full command arguments.

## HTTP contract

- `GET /api/v1/status` returns initialization state and product version.
- `POST /api/v1/initialize` accepts `{ "organization": "..." }`.
- `GET /api/v1/certificates` returns safe issued-certificate metadata.
- `POST /api/v1/certificates/rsa` accepts an issuance request plus
  `"confirm_server_key_generation": true`.
- `POST /api/v1/certificates/tlcp` accepts the same identity request and explicit
  key-generation confirmation.
- `GET /api/v1/certificates/{id}/files/{file}` downloads allowlisted leaf files.
- `GET /api/v1/roots/{rsa|sm2}` downloads only the selected public root certificate.
- JSON errors use a stable machine code and a human-readable message; internal
  paths and cryptographic command output are excluded.

## Security and failure constraints

- The default and supported v0.1 listener remains `127.0.0.1`; starting with a
  non-loopback address is rejected until authentication is implemented.
- Mutation endpoints accept only JSON, enforce a small request-body limit, reject
  unknown fields, and validate `Origin` when it is present.
- Security headers remain enabled. Private-key responses add
  `Cache-Control: no-store`, `Pragma: no-cache`, `X-Content-Type-Options: nosniff`,
  and attachment disposition.
- Route parameters are opaque allowlisted identifiers, never joined unchecked to
  a filesystem path. Symlinks and unsupported file names are rejected.
- Existing names return HTTP 409. Invalid input returns HTTP 400. Crypto timeout
  or failure returns HTTP 502/504 without publishing a partial bundle.
- Concurrent duplicate-name requests publish at most one bundle. Concurrent
  distinct requests never reuse serials.
- The Web UI must work without a JavaScript framework or external CDN and must
  never render unescaped certificate/request values.

## Required test layers

- Handler unit tests for status, initialization, RSA, TLCP, listing, and downloads.
- Table and property tests for JSON limits, unknown fields, route IDs, filenames,
  origins, SAN parsing, and error-to-status mapping.
- Integration tests using a temporary data directory and pinned Tongsuo.
- Concurrent duplicate and distinct issuance tests under the race detector.
- Negative download tests proving CA keys, arbitrary paths, symlinks, temporary
  files, CSRs, and configuration files cannot be retrieved.
- Manual mutants for explicit key confirmation, loopback enforcement, private-file
  allowlist, duplicate conflict, and HTML escaping.
- Real browser/API smoke test plus retained PKI core gauntlet.

## Acceptance boundary

The project owner authorized implementation to continue without additional
checkpoint approvals. The accepted choices are loopback-only/no authentication
for this increment, explicit but repeatable leaf private-key download, and
deferring revocation/OCSP to the next independently verified increment.
