# Evidence: Linux installation packages

- Implementation commit: `0f8ea368de5d38f7ab88fdd7b1f60a277e7fa93e`
- Spec: `docs/SPEC-packaging.md`
- Spec approval: covered by the project owner's standing autonomous authorization;
  no separate correlation-breaking review was obtained for this phase.
- Risk tier: 3, because installation runs privileged maintainer scripts and the
  resulting service owns durable CA private keys.
- Build host: Apple Container CLI 1.1.0 on Apple silicon, using x86_64 Rosetta
  containers.
- Application toolchain: Go 1.22 Bookworm image.
- Crypto source: Tongsuo 8.4.0 commit
  `a8ae0925d26de3b449f7a21767910cd41291bcd8`.

## Scenario mapping

| Spec behavior | Executable evidence | Result |
| --- | --- | --- |
| Reproducible RPM/DEB and notices | `scripts/build-packages-apple-container.sh`; payload checks in install smoke | Passed |
| Static Go binary and glibc 2.17 Tongsuo floor | CentOS 7 build plus `TONGSUO-GLIBC-VERSIONS.txt` guard | Highest symbol `GLIBC_2.17` |
| Unprivileged, loopback-only service | `tools/package-contract-test.sh`; installed-package checks | Passed on both targets |
| Packaged pinned Tongsuo only | build manifest, version assertion, installed issuance smoke | Tongsuo 8.4.0 |
| Existing CA/config survive upgrade/removal | RPM operator-owned config; Debian conffile; uninstall hash checks | Passed |
| RSA/TLCP, CRL, and OCSP work after installation | `tools/installed-package-smoke.sh` | Passed on CentOS 7 and Debian 12 |
| Required project and third-party licenses | RPM installed files; direct DEB payload inspection | Passed |
| No network download during installation | package scripts and payload contract | Passed |

## Final gauntlet

The final fresh source gauntlet ran in the pinned Go 1.22 x86_64 image after the
last implementation edit:

```sh
CERTARIUM_OPENSSL=/runtime/opt/certarium/bin/openssl \
CERTARIUM_TONGSUO_LICENSE=/runtime/usr/share/doc/certarium/Tongsuo-LICENSE.txt \
./tools/gauntlet.sh
```

Results:

- formatting: zero unformatted files;
- static analysis: `go vet ./...` passed;
- race and randomized-order suite: all packages passed with `-race -shuffle=on`;
- PKI coverage: 74.9% statements; `RespondOCSP` 75.9%;
- existing PKI mutants: 8/8 killed;
- existing Web/API mutants: 7/7 killed;
- package/security mutants: 7/7 killed;
- real HTTP health check: passed;
- real Web/API RSA and TLCP issuance, OCSP good-to-revoked, CRL, and secure
  download smoke: passed;
- dependency, license, and committed-secret checks: passed;
- terminal result: `GAUNTLET PASSED`.

The package-specific real execution was then run with:

```sh
./scripts/test-install-packages-apple-container.sh
```

Both target images installed the package, initialized fresh RSA and SM2 CAs,
issued RSA and TLCP certificates, validated OCSP `good`, revoked both bundles,
validated OCSP `revoked`, verified both CRLs, removed the package, and verified
the pre-removal hashes of both root private keys. Terminal results were:

- `CENTOS 7 RPM INSTALL/UNINSTALL SMOKE PASSED`
- `DEBIAN 12 DEB INSTALL/UNINSTALL SMOKE PASSED`
- `ALL PACKAGE INSTALL SMOKES PASSED`

## Artifacts

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `certarium-0.1.0-1.el7.x86_64.rpm` | 5,565,596 | `bdf8fd48bac7f1446447434e6f263dff01263320b1c37d99bdd294f7be03948d` |
| `certarium_0.1.0-1_amd64.deb` | 4,160,660 | `e6d3bab29f1c5aa55eb50553c80d755ac8620492b9ef50d891838da6a020b8f4` |

Generated packages remain ignored build artifacts under `dist/`; the repository
contains the complete reproducible build and test entry points instead.

## Failures found and resolved

1. CentOS Vault HTTPS was incompatible with CentOS 7's retired TLS stack. The
   build now uses the Kernel.org CentOS Vault mirror over archive HTTP while
   Tongsuo source checkout remains in a modern TLS-capable stage and is pinned
   by commit hash.
2. The first RPM build used an unconditional empty module glob. The package now
   normalizes both `lib` and `lib64` provider locations into a guaranteed private
   module directory.
3. Maintainer scripts invoked `systemctl` in containers without a running
   systemd. Calls are now guarded by `/run/systemd/system` and remain active on
   real systemd hosts.
4. RPM would remove an unchanged config file during erase. RPM now owns a
   default template and creates the operator-owned config only when absent;
   upgrade and removal do not overwrite or remove it.
5. Debian slim intentionally path-excludes installed documentation. The DEB
   license files are therefore verified directly in the package payload before
   runtime checks; normal Debian systems without that image policy install them.

## Known limits

- Only x86_64 packages are produced in this phase.
- CentOS 7 and Debian 12 are the clean-install test targets; other RPM/DEB
  distributions are not yet claimed.
- systemd enable/start behavior is specified and statically verified, but the
  clean containers do not boot systemd as PID 1; the service executable is run
  directly as the packaged unprivileged account for real PKI testing.
- Reproducible entry points and pinned sources are present, but bit-for-bit
  deterministic package output across different build dates is not claimed.
