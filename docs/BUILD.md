# Build and verification

Certarium is a Go service plus a pinned Tongsuo 8.4.0 runtime. Release packages
are built in CentOS 7 userspace to retain the x86_64 glibc 2.17 baseline.

```sh
# Apple Silicon with Apple Container
./scripts/build-packages-apple-container.sh
./scripts/test-install-packages-apple-container.sh

# x86_64 Linux with Docker
./scripts/build-packages-linux.sh
./scripts/test-install-packages-linux.sh
```

Artifacts and `SHA256SUMS` go to `dist/`. `tools/gauntlet.sh` is the single
verification entry point. No CA, key, password, certificate database, backup,
or audit log belongs in source control or release packages.
