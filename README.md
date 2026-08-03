# CertLab GM

CertLab GM is a local PKI workbench for development and interoperability labs.
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

## Status

The repository is being reshaped into the first runnable MVP. See
`docs/PRODUCT.md` for scope and acceptance criteria.
