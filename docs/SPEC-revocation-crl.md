# Executable specification: certificate revocation and CRL

- Status: approved under standing project-owner authorization on 2026-08-03
- Risk tier: 3 (durable CA status, concurrent mutation, public revocation artifacts)
- Dependencies: existing Go standard library and pinned Tongsuo only
- Out of scope: OCSP transport/responder, scheduled refresh daemon, delta CRLs,
  indirect CRLs, and non-loopback administration

## Scenarios

1. CA initialization creates independent, private RSA and SM2 CA databases and
   monotonically increasing CRL numbers without exposing them through Web routes.
2. Successful RSA issuance records the certificate as valid in the RSA database.
3. Successful TLCP issuance records both signing and encryption certificates as
   valid in the SM2 database with distinct serials.
4. Revoking an RSA bundle changes its certificate state from valid to revoked and
   atomically publishes a newly signed RSA CRL.
5. Revoking a TLCP bundle revokes both certificates as one operator action and
   atomically publishes a newly signed SM2 CRL. A partial pair is an error.
6. Repeating revocation is idempotent at the API boundary and does not report a
   revoked certificate as valid again.
7. Inventory returns `valid` or `revoked` without exposing CA database paths or
   raw Tongsuo output.
8. Public CRLs are downloadable with the correct content type and no private CA
   material is reachable through the CRL route.
9. A real Tongsuo verification proves that the published CRL is signed by the
   matching root and contains the revoked certificate serial number.

## HTTP contract

- `POST /api/v1/certificates/{id}/revoke` revokes the complete bundle.
- `GET /api/v1/crl/{rsa|sm2}` downloads the current PEM CRL.
- Certificate list records include `state`.
- Invalid identifiers return 404, already-revoked bundles return the same stable
  revoked result, and crypto timeout/failure maps to 504/502.

## Failure and security constraints

- Revocation and CRL-number state changes are serialized per service instance.
- CA index, CRL-number, temporary configuration, and unpublished CRLs remain mode
  0600 in the private data tree.
- Tongsuo failure must not replace a previously valid published CRL.
- A TLCP pair is never presented as fully revoked if only one certificate was
  updated; the inconsistent state must be surfaced for repair.
- Route values are allowlisted and never interpolated into a shell command.
- Audit/error output excludes certificate private keys and absolute internal paths.

## Required evidence

- RED/GREEN unit tests for state transitions, idempotency, pair consistency,
  download boundary, and error mapping.
- Race test for concurrent repeated revocation.
- Real Tongsuo RSA and SM2 CRL generation, signature verification, and revoked
  serial inspection.
- Manual mutants for skipped database registration, skipped second TLCP revoke,
  stale CRL publication, and revoked-state reporting.
- Updated gauntlet, Web smoke, and evidence report.
