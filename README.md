# Certarium

Certarium is a self-hosted PKI workbench for development and interoperability labs.
It makes RSA and Chinese-commercial-cryptography certificate issuance easier
without acting as a TLS terminator, reverse proxy, or load balancer.

## Product boundary

Included:

- private RSA and SM2 CA initialization;
- RSA server certificate issuance;
- TLCP signing/encryption certificate-pair issuance;
- DNS, IPv4, and IPv6 SAN handling;
- certificate inventory, download, revocation, CRL, and OCSP;
- a small Web UI and automation API.

Excluded:

- application TLS/TLCP termination;
- load balancing and upstream health checks;
- HA, multi-tenant production PKI, and HSM integration in v1.

The existing Nginx + Tongsuo experiment is retained under `examples/` as a
consumer interoperability example, not as part of the product data plane.

## Project authorship and licensing

The product concept and direction are by Carl Flynn. Implementation and
verification are AI-assisted with OpenAI Codex; see
[`AI_ASSISTED_DEVELOPMENT.md`](AI_ASSISTED_DEVELOPMENT.md).

Original Certarium code is licensed under `AGPL-3.0-only`. A separate commercial
license is available for organizations that cannot use the AGPL; see
[`COMMERCIAL_LICENSE.md`](COMMERCIAL_LICENSE.md). Third-party components retain
their own licenses as documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Status

The repository is being reshaped into the first runnable MVP. See
`docs/PRODUCT.md` for scope and acceptance criteria.

## Linux packages

The packaging pipeline emits self-contained x86_64 RPM and DEB packages. Each
package contains the Certarium service and the pinned Tongsuo 8.4.0 executable;
it does not download dependencies or generate CA material during installation.

- CentOS 7: install `certarium-0.1.0-1.el7.x86_64.rpm` with the system package
  manager.
- Debian: install `certarium_0.1.0-1_amd64.deb` with the system package manager.
- The systemd service runs as the unprivileged `certarium` account and listens
  on `127.0.0.1:8080` by default.
- Durable PKI state is stored in `/var/lib/certarium`; ordinary package removal
  preserves that state and `/etc/certarium/certarium.env`.

On an Apple-silicon Mac with Apple Container installed, reproduce both packages
and their clean-install tests with:

```sh
./scripts/build-packages-apple-container.sh
./scripts/test-install-packages-apple-container.sh
```

Generated packages and hashes are written to `dist/`. The first build is slow
because Tongsuo is compiled using the CentOS 7 x86_64 toolchain to prove the
glibc 2.17 compatibility floor; subsequent builds reuse that layer.
