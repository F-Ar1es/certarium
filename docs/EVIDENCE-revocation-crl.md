# Revocation and CRL verification evidence

- Verification date: 2026-08-03 (Asia/Shanghai)
- Environment: Apple Container, Linux arm64, Go 1.22
- Crypto: pinned Tongsuo 8.4.0 (`a8ae0925d26de3b449f7a21767910cd41291bcd8`)
- Result: **passed**

## Real execution evidence

The persisted Web smoke test performed the following through the HTTP API:

1. Initialized independent RSA and SM2 roots and private CA databases.
2. Issued an RSA certificate with serial `01`.
3. Issued a TLCP signing/encryption pair with serials `02` and `03`.
4. Revoked the RSA bundle and the complete TLCP pair.
5. Downloaded both published CRLs.
6. Verified each CRL signature against its matching root with Tongsuo.
7. Confirmed the RSA CRL contains serial `01` and the SM2 CRL contains both
   serials `02` and `03`.

The inventory changed both bundles from `valid` to `revoked`. Twelve concurrent
repeat requests produced one CRL publication and twelve stable revoked results.

## Failure and mutation evidence

- A previously published CRL remained byte-for-byte unchanged when revocation or
  CRL generation failed.
- Seven PKI mutants and seven Web/API mutants were killed (14/14 total), including
  skipped CA registration, ignored CRL-generation failure, incomplete TLCP-pair
  revocation, and incorrect revoked-state reporting.
- Race detection, shuffled tests, `go vet`, formatting, real crypto integration,
  build, HTTP health, dependency/license checks, and secret scanning passed.
- PKI statement coverage after adding the CRL engine is 74.8%; `PublishCRL` is
  71.4% covered. The real Tongsuo integration covers RSA and SM2 success paths,
  while injected tests cover revocation and generation failures.

## Boundary

This evidence covers downloadable full CRLs and local administrative revocation.
It does not claim an OCSP responder, scheduled CRL refresh, authentication,
non-loopback administration, delta CRLs, or HSM-backed CA keys.
