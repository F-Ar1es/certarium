# Certarium v0.1 release evidence

- Evidence date: 2026-08-03 (Asia/Shanghai)
- Verified source: `375f01f60dd7a47eca7549dadd3646eeb4c744b9`
- Risk calibration: old-coder Tier 3
- Specification: `docs/SPEC-v0.1-release.md`
- Spec approval: no separate line-by-line approval was obtained; implementation
  proceeded under the owner's explicit standing autonomous authorization. This
  weakens confidence only in specification completeness, not the recorded runs.
- Application dependencies: Go standard library only
- Crypto runtime: Tongsuo 8.4.0, commit
  `a8ae0925d26de3b449f7a21767910cd41291bcd8`

## Fresh final gauntlet

`tools/gauntlet.sh` completed after the final source edit with `GAUNTLET PASSED`
inside a Linux x86_64 container under Rosetta, using the packaged Tongsuo binary.

- `gofmt -l .`: no output
- `go vet ./...`: zero findings
- `go test -race -shuffle=on -count=1 ./...`: all packages passed
- Real encrypted-key Tongsuo integration: RSA and TLCP issuance, CRL, OCSP,
  revocation, and encrypted CA-key reopen passed
- PKI statement coverage: 75.9%
- Core/CRL/OCSP manual mutants: 7/7 killed
- Web/API manual mutants: 10/10 killed
- Packaging manual mutants: 7/7 killed
- Release security mutants: 5/5 killed
- Total hand-written mutants: 29/29 killed
- Real health request: HTTP response contained `"status":"ok"`
- Real Web/API smoke: initialization, RSA with DNS/IP SAN, TLCP pair, inventory,
  certificate verification, revocation, CRL, OCSP, and private no-cache response
  passed
- Dependency inventory: module `certarium` only
- License files: AGPL, notice, commercial-license notice, AI disclosure, and
  Tongsuo license present
- Committed secret patterns: none found

## Package execution evidence

`scripts/build-packages-apple-container.sh` rebuilt both packages from the
verified source. `scripts/test-install-packages-apple-container.sh` then passed:

- CentOS 7 x86_64: clean RPM install, Tongsuo 8.4.0, health, encrypted RSA/TLCP
  CA and issuance, CRL/OCSP good-to-revoked transition, same-version reinstall
  hash preservation, encrypted backup/restore, ordinary uninstall state
  preservation.
- Debian 12 x86_64: the identical DEB scenario passed.
- Tongsuo dynamic symbol audit found no requirement newer than glibc 2.17.

Artifacts:

```text
61d5afeeffa97e8c92b5066b435d7a871afbdda7eaa7475bd7649611a79b6764  certarium-0.1.0-1.el7.x86_64.rpm
9f34dab8bc1a6b6b31256803829f8c55e1e6aa611ca75a697cf90193a6ad698b  certarium_0.1.0-1_amd64.deb
```

## Acceptance mapping

- Audit/fail-closed/no-secret/concurrency: `internal/audit/log_test.go` and
  `internal/webapp/handler_test.go`; audit and Web mutants.
- Encrypted credential loading and no argv secret: `internal/pki/passphrase_test.go`,
  `internal/pki/engine_test.go`, and real `internal/pki/integration_test.go`.
- Encrypted backup integrity, hostile paths, wrong password, corruption, and
  replacement refusal: `internal/backup/backup_test.go`; package round trips.
- Bundle/root download allowlists and symlink refusal:
  `internal/webapp/pki_service_test.go`.
- Upgrade/removal preservation and package hardening: installed-package smokes,
  `tools/package-contract-test.sh`, and package mutants.
- CI/release reproducibility: `.github/workflows/ci.yml`,
  `.github/workflows/release.yml`, and shared Linux/Apple packaging scripts.

## Explicitly unavailable / known limits

- Not executed: a real VM booted with systemd as PID 1, including reboot. The
  runnable check is `tools/systemd-vm-smoke.sh`; the owner stated no VM was
  currently available. Container package tests do not claim to prove boot-time
  service enablement or journal behavior.
- Not applicable to Go: a separate static type checker; Go compilation and vet
  provide the language's static checks.
- Property framework not added: parsing/serialization invariants are covered by
  table, round-trip, corruption, concurrent, and adversarial tests without a new
  dependency.
- v0.1 remains a loopback-only lab PKI. Authentication/RBAC, HSM/PKCS#11, HA,
  multi-tenancy, ARM64 packages, public-trust operation, TLS termination, and
  load balancing are not claimed.

This evidence proves the executable specification only to the extent its
constraints are complete; it is not a claim of formal verification or
production/public-CA suitability.
