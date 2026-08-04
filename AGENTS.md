# Certarium repository instructions

## Project purpose

Certarium is a loopback-only private PKI workbench that makes standard RSA and
SM2/TLCP test certificates easier to obtain for product development and
interoperability labs. It is not a TLS terminator, load balancer, public CA, or
production multi-tenant service.

## Required workflow

All coding work in this repository must use the installed `old-coder` skill.
Before implementation, produce an executable SPEC for human approval. Then use
RED, GREEN, REFACTOR, GAUNTLET, and EVIDENCE. Persist the gauntlet and evidence
artifacts in the repository and push meaningful checkpoints to GitHub.

For documentation-only changes, use a scoped executable contract and run the
checks relevant to the changed files. Do not claim that application tests ran
when only documentation checks were executed.

## Verification entry points

- Complete release gauntlet: `./tools/gauntlet.sh`
- README/Codex contract: `./tools/readme-contract-test.sh`
- Package contract: `./tools/package-contract-test.sh`
- Real systemd VM check: `./tools/systemd-vm-smoke.sh PACKAGE`

## Safety and compatibility

- Never commit generated CA material, private keys, passwords, tokens, runtime
  state, certificate databases, backups, or audit logs.
- Keep the Web/API listener loopback-only unless a separately approved security
  design adds authentication and authorization.
- Preserve the CentOS 7 x86_64/glibc 2.17 compatibility floor and pinned
  Tongsuo 8.4.0 runtime unless the executable SPEC explicitly changes them.
- Preserve durable state and `/etc/certarium/ca.pass` across reinstall, upgrade,
  and ordinary package removal.
- Do not add dependencies without recording their purpose and license in the SPEC.

## Documentation and attribution

- Keep `README.md` and `README-zh.md` aligned when product behavior, installation,
  supported platforms, security boundaries, or commands change.
- Product scope and release decisions remain human decisions by Carl Flynn.
  Disclose material OpenAI Codex assistance in `AI_ASSISTED_DEVELOPMENT.md` and
  evidence reports without assigning copyright, maintainership, or accountability
  to the AI tool.
