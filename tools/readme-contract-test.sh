#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
EN="$ROOT/README.md"
ZH="$ROOT/README-zh.md"
AGENTS="$ROOT/AGENTS.md"
AI="$ROOT/AI_ASSISTED_DEVELOPMENT.md"

test -s "$EN"
test -s "$ZH"
grep -F '[简体中文](README-zh.md)' "$EN"
grep -F '[English](README.md)' "$ZH"

for file in "$EN" "$ZH"; do
    grep -F 'Certarium' "$file"
    grep -F 'Tongsuo 8.4.0' "$file"
    grep -F 'certarium-0.1.0-1.el7.x86_64.rpm' "$file"
    grep -F 'certarium_0.1.0-1_amd64.deb' "$file"
    grep -F '127.0.0.1:8080' "$file"
    grep -F 'systemctl enable --now certarium' "$file"
    grep -F 'TLCP' "$file"
    grep -F 'OCSP' "$file"
    grep -F 'certarium-backup' "$file"
    grep -F 'OpenAI Codex' "$file"
done

grep -F 'company products' "$EN"
grep -F '公司产品' "$ZH"
grep -F 'old-coder' "$AGENTS"
grep -F './tools/gauntlet.sh' "$AGENTS"
grep -F './tools/readme-contract-test.sh' "$AGENTS"
grep -F 'OpenAI Codex' "$AI"
grep -F 'not listed as copyright owners' "$AI"

echo 'README/CODEX CONTRACT PASSED'
