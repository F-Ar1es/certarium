# README and Codex repository integration specification

- Date: 2026-08-04
- Risk tier: old-coder Tier 1 (documentation and repository instructions only)
- Approval: implemented under the owner's explicit request and standing
  authorization to complete repository work and push checkpoints.
- Dependencies: none.

## Acceptance scenarios

1. `README.md` is the English landing page and links prominently to
   `README-zh.md`; the Chinese page links back to English.
2. Both pages state the business purpose: reduce repeated setup work when
   company products need standard TLS or Chinese commercial cryptography/TLCP
   certificates for development and interoperability tests.
3. Both pages document RSA, SM2/TLCP dual certificates, SANs, inventory,
   revocation, CRL, OCSP, audit, encrypted CA keys, backup/restore, Web UI,
   supported x86_64 packages, loopback access, and v0.1 exclusions.
4. Both pages provide a minimal install-to-first-certificate path without
   claiming unverified platforms or production/public-CA suitability.
5. The repository attributes product direction and release decisions to Carl
   Flynn and implementation/verification assistance to OpenAI Codex.
6. `AGENTS.md` gives Codex a concise project map, required old-coder workflow,
   validation entry points, safety constraints, and documentation language rule.
7. AI attribution is disclosure, not transfer of copyright, maintainership, or
   accountability. No fabricated Codex GitHub account is claimed.

## Verification

- `tools/readme-contract-test.sh` checks required links, product boundary,
  commands, supported package names, Codex disclosure, and AGENTS instructions.
- `git diff --check` verifies Markdown whitespace.
- Existing source tests are not rerun because no executable code, packaging,
  configuration, or workflow behavior changes.
