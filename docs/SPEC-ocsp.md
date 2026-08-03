# Executable specification: standard OCSP responder

- Status: approved under standing project-owner authorization on 2026-08-03
- Risk tier: 3 (online CA-status protocol, untrusted binary requests, CA signing key use)
- Dependencies: existing Go standard library and pinned Tongsuo only
- Protocol: DER OCSP request/response over HTTP, not a JSON substitute

## Scenarios

1. Every successful RSA or TLCP issuance refreshes the matching CA index so the
   new certificate has an online `good` status before any revocation.
2. Every successful revocation refreshes the index before the API reports the
   bundle as revoked.
3. `POST /ocsp/rsa` accepts a bounded `application/ocsp-request` body and returns
   a signed `application/ocsp-response` DER body from the RSA issuer.
4. `POST /ocsp/sm2` provides the same behavior for SM2/TLCP certificates.
5. Tongsuo verification reports `good` for a known valid certificate, `revoked`
   after revocation, and `unknown` for a serial absent from that issuer database.
6. Malformed, empty, oversized, wrong-content-type, and cross-origin requests are
   rejected without invoking Tongsuo or exposing CA paths/output.
7. OCSP response generation is bounded by the existing crypto timeout and leaves
   no request/response temporary files after success or failure.

## Security constraints

- Request bodies are capped at 16 KiB and written only to a private temporary
  directory with mode 0700; request files use mode 0600.
- No request-derived value becomes a command name, path, config fragment, shell
  string, or response header.
- Only `rsa` and `sm2` issuer routes are accepted.
- Responses use `Cache-Control: no-store` for the first implementation; responder
  caching may be added only with explicit `thisUpdate`/`nextUpdate` handling.
- The CA issuer signs its own OCSP responses directly. A delegated responder
  certificate and HSM-backed signing are later hardening options.

## Required evidence

- Handler tests for MIME types, size limits, invalid kinds, and error mapping.
- Engine tests for private temporary files, cleanup, timeout/failure, and issuer
  allowlisting.
- Real Tongsuo request/response verification for RSA good→revoked and SM2
  good→revoked. Unknown status must be demonstrated with a foreign serial request.
- Race tests for simultaneous status requests and mutations.
- Manual mutants for wrong issuer index, missing body cap, stale issuance index,
  and response content-type.
- Updated gauntlet, HTTP smoke test, and evidence report.
