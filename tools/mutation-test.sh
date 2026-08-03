#!/bin/sh
set -eu

GO_BIN=${GO_BIN:-go}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d)
CURRENT_FILE=

restore() {
    if [ -n "$CURRENT_FILE" ] && [ -f "$TMP_DIR/original" ]; then
        cp "$TMP_DIR/original" "$CURRENT_FILE"
    fi
}

cleanup() {
    restore
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

run_mutant() {
    name=$1
    file=$2
    before=$3
    after=$4
    test_name=$5

    CURRENT_FILE="$ROOT/$file"
    cp "$CURRENT_FILE" "$TMP_DIR/original"
    if ! grep -F "$before" "$CURRENT_FILE" >/dev/null; then
        echo "mutation anchor missing: $name" >&2
        exit 1
    fi
    sed "s#$before#$after#" "$TMP_DIR/original" >"$CURRENT_FILE"
    if "$GO_BIN" test ./internal/pki -run "$test_name" >"$TMP_DIR/test.log" 2>&1; then
        echo "SURVIVED: $name" >&2
        cat "$TMP_DIR/test.log" >&2
        exit 1
    fi
    restore
    CURRENT_FILE=
    rm -f "$TMP_DIR/original"
    echo "KILLED: $name"
}

cd "$ROOT"
run_mutant \
    validity-upper-bound \
    internal/pki/pki.go \
    'req.ValidDays > 825' \
    'req.ValidDays > 826' \
    TestValidateRequestRejectsHostileAndInvalidInputs

run_mutant \
    persistent-serial-increment \
    internal/pki/pki.go \
    'current.NextSerial++' \
    'current.NextSerial += 0' \
    TestNextSerialIsUniqueUnderConcurrencyAndPersists

run_mutant \
    tlcp-signing-key-usage \
    internal/pki/profile.go \
    'keyUsage = "digitalSignature"' \
    'keyUsage = "keyEncipherment"' \
    TestIssueTLCPUsesDistinctKeysSerialsAndProfiles

run_mutant \
    tlcp-encryption-key-usage \
    internal/pki/profile.go \
    'keyUsage = "keyEncipherment,dataEncipherment,keyAgreement"' \
    'keyUsage = "digitalSignature"' \
    TestIssueTLCPUsesDistinctKeysSerialsAndProfiles

run_mutant \
    command-timeout \
    internal/pki/runner.go \
    'timed, cancel := context.WithTimeout(ctx, r.Timeout)' \
    'timed, cancel := context.WithCancel(ctx)' \
    TestCommandRunnerReturnsStableTimeoutError

run_mutant \
    crl-database-registration \
    internal/pki/engine.go \
    'validCerts...), revokedCerts...)' \
    'validCerts...), validCerts...)' \
    TestPublishCRLUsesPrivateDatabaseAndDoesNotReplaceOnFailure

run_mutant \
    stale-crl-on-generation-failure \
    internal/pki/engine.go \
    'return fmt.Errorf("generate CRL: %w", err)' \
    'return nil' \
    TestPublishCRLUsesPrivateDatabaseAndDoesNotReplaceOnFailure

echo "All manual mutants were killed."
