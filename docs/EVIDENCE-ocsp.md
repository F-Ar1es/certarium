# Standard OCSP verification evidence

- Verification date: 2026-08-03 (Asia/Shanghai)
- Environment: Apple Container, Linux arm64, Go 1.22
- Crypto: pinned Tongsuo 8.4.0 (`a8ae0925d26de3b449f7a21767910cd41291bcd8`)
- Protocol: DER OCSP request/response over HTTP
- Result: **passed**

## Real protocol evidence

- Tongsuo generated OCSP DER requests for the issued RSA and SM2 certificates.
- Certarium accepted the requests through `POST /ocsp/rsa` and `/ocsp/sm2` with
  `application/ocsp-request` and returned `application/ocsp-response` DER bodies.
- Tongsuo verified each signed response against the corresponding issuer.
- Both RSA and SM2 status transitions were observed as `good` before revocation
  and `revoked` after revocation.
- A request for absent decimal serial `2147483647` produced `unknown`.
- Issuance now refreshes the matching CA index before reporting success, preventing
  a freshly issued certificate from appearing unknown due to stale status data.

## Security and failure evidence

- Empty, oversized, wrong-MIME, cross-origin, and unknown-issuer requests are
  rejected before response generation.
- Request bodies are limited to 16 KiB. Temporary request/response files are
  private and removed after success or failure.
- Only the allowlisted RSA or SM2 issuer index can be selected.
- Responses currently use `Cache-Control: no-store`.
- The command boundary remains argument-based without shell interpretation and
  inherits the existing cryptographic timeout.

## Gauntlet evidence

- Race detection, shuffled tests, real RSA/SM2 crypto integration, CRL checks,
  HTTP smoke tests, build, vet/format, license/dependency checks, and secret scan
  passed.
- PKI statement coverage: 74.9%; `RespondOCSP`: 75.9%.
- Eight PKI mutants and ten Web/API mutants were killed (18/18), including wrong
  issuer index, missing OCSP body limit, incorrect response MIME, and skipped
  post-issuance status refresh.

## Boundary

The issuer CA signs responses directly and each request invokes Tongsuo. Delegated
OCSP responder certificates, response caching, process pooling, HSM-backed signing,
authentication, and non-loopback administration remain future hardening work.
