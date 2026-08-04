# README and Codex integration evidence

- Date: 2026-08-04 (Asia/Shanghai)
- Verified source commit: `7e82fcf`
- Specification: `docs/SPEC-readme-codex.md`
- Risk tier: old-coder Tier 1

## RED

`./tools/readme-contract-test.sh` was run before implementation. It failed
because `README-zh.md` did not exist and the required bilingual/product/Codex
contract was not satisfied.

## Final fresh verification

Executed after the final non-evidence edit:

```text
./tools/readme-contract-test.sh
README/CODEX CONTRACT PASSED

git diff --check
MARKDOWN WHITESPACE PASSED
```

The contract verifies:

- reciprocal English and Simplified Chinese navigation;
- purpose, supported package names, Tongsuo version, loopback URL, service
  command, TLCP, OCSP, backup CLI, and OpenAI Codex disclosure on both pages;
- company-product testing purpose in both languages;
- old-coder workflow and verification commands in `AGENTS.md`;
- human ownership/accountability boundary in the AI disclosure.

Local targets referenced from the landing pages were also checked as present
and non-empty: both READMEs, `AGENTS.md`, AI disclosure, product, installation,
operations, backup, security, release specification, and release evidence.

## Research finding and attribution decision

The public old-coder repository marks Claude involvement with free-form Git
`Co-Authored-By` trailers and separately documents Claude Code support. It does
not embed Claude in the application. OpenAI's Codex documentation identifies
repository-level `AGENTS.md` as the durable project-instruction mechanism, but
no official Codex co-author email convention was found.

Certarium therefore uses:

- `AGENTS.md` for executable Codex/project instructions;
- README and `AI_ASSISTED_DEVELOPMENT.md` for visible disclosure;
- `AI-Assisted-By: OpenAI Codex` as an attribution-only commit trailer.

It deliberately does not fabricate a GitHub bot identity or assign copyright,
maintainership, or release responsibility to Codex.

## Skipped layers

- Go tests, race tests, Tongsuo execution, package rebuilding, coverage, and
  source mutation were not rerun because this checkpoint changes only Markdown
  documentation and a documentation contract script. Application, packaging,
  workflow, and runtime configuration files are unchanged.
