# PKI core verification evidence

- Verification date: 2026-08-03 (Asia/Shanghai)
- Verified source commit: `b64933c`
- Host: Apple silicon macOS using Apple Container
- Test environment: Linux `arm64`, Go 1.22 Bookworm image
- Crypto implementation: Tongsuo 8.4.0, source commit
  `a8ae0925d26de3b449f7a21767910cd41291bcd8`
- Command: `GO_BIN=/usr/local/go/bin/go GOFMT_BIN=/usr/local/go/bin/gofmt ./tools/gauntlet.sh`
- Result: **passed**

## Executed layers

| Layer | Result | Evidence |
| --- | --- | --- |
| Formatting | Passed | `gofmt -l` returned no files |
| Static analysis | Passed | `go vet ./...` |
| Unit tests | Passed | All packages passed |
| Property tests | Passed | 500 hostile-input and 500 valid-DNS generated cases |
| Race detection | Passed | `go test -race -shuffle=on -count=1 ./...` |
| Real crypto integration | Passed | RSA root/server and SM2 root/TLCP signing+encryption certificates generated and verified with pinned Tongsuo |
| Coverage | Passed | PKI package statement coverage: 75.5%; validation and profile construction: 100% |
| Manual mutation | Passed | 5 of 5 mutants killed |
| Build | Passed | `cmd/certarium` built with `-trimpath` |
| Real HTTP check | Passed | `GET /api/v1/health` returned `{"status":"ok",...}` |
| Dependency inventory | Passed | `go list -m all` reported only the local `certarium` module |
| License inventory | Passed | Project notices and bundled Tongsuo license present |
| Secret scan | Passed | No private-key blocks or common GitHub/AWS credential patterns found in tracked files |

## Mutation results

The persisted mutation runner deliberately introduced and proved detection of:

1. An off-by-one certificate validity limit.
2. A disabled persistent serial-number increment.
3. An incorrect TLCP signing-certificate key usage.
4. An incorrect TLCP encryption-certificate key usage.
5. A disabled cryptographic-command timeout.

All mutants caused their targeted tests to fail and were automatically restored.

## Skipped or substituted layers

- `staticcheck` was not installed in the pinned image. `go vet` was executed as
  the available static-analysis layer. Adding another downloaded tool is deferred
  until its version and license are pinned in the build manifest.
- `gitleaks` was not installed. The gauntlet used a tracked-file pattern scan for
  private keys and common GitHub/AWS credential formats. A pinned dedicated secret
  scanner remains appropriate for the release pipeline.
- Automated dependency-vulnerability scanning was not applicable to the current
  Go module because it has no third-party Go module dependencies. Tongsuo remains
  an external pinned component and must be monitored separately before release.

## Reproduction

Build the pinned test image with `scripts/build-tongsuo-test-image.sh`, then mount
the repository into that image and execute `tools/gauntlet.sh`. The script refuses
to run the real integration layer unless `CERTARIUM_OPENSSL` identifies Tongsuo,
and verifies that the executable reports Tongsuo 8.4.0.
