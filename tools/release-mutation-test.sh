#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
cp -R "$ROOT" "$TMP/source"
cd "$TMP/source"

mutate_and_expect_failure() {
    name=$1
    expression=$2
    replacement=$3
    test_command=$4
    file=$(printf '%s' "$name" | cut -d: -f1)
    cp "$ROOT/$file" "$file"
    perl -0pi -e "s/\Q$expression\E/$replacement/" "$file"
    if sh -c "$test_command" >"$TMP/mutant.log" 2>&1; then
        echo "SURVIVED: $name" >&2
        cat "$TMP/mutant.log" >&2
        exit 1
    fi
    echo "KILLED: $name"
}

mutate_and_expect_failure 'internal/audit/log.go:public-mode' 'file.Chmod(0600)' 'file.Chmod(0644)' 'go test ./internal/audit'
mutate_and_expect_failure 'internal/pki/passphrase.go:public-passphrase' 'info.Mode().Perm()&0077 != 0' 'false' 'go test ./internal/pki'
mutate_and_expect_failure 'internal/backup/backup.go:plaintext-backup' 'temp.Write(encrypted)' 'temp.Write(plain)' 'go test ./internal/backup'
mutate_and_expect_failure 'internal/pki/engine.go:plaintext-ca' '"-aes-256-cbc", "-pass",' '"-pass",' 'go test ./internal/pki'
mutate_and_expect_failure 'internal/webapp/handler.go:no-audit-preflight' 'if err := log.Ready(); err != nil {' 'if false {' 'go test ./internal/webapp'

echo 'RELEASE MUTATION TEST PASSED (5/5 killed)'
