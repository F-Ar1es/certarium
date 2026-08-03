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
