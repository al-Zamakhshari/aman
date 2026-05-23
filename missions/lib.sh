#!/usr/bin/env bash
# lib.sh — shared helpers for aman mission tests
set -euo pipefail

# ── Counters ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
MISSION_NAME="${MISSION_NAME:-unknown}"

# ── Formatting ───────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

mission_start() {
    echo ""
    echo -e "${BOLD}━━━ Mission: $1 ━━━${RESET}"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✓${RESET} $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}✗${RESET} $1"
}

mission_end() {
    local total=$((PASS + FAIL))
    echo ""
    if [ "$FAIL" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}$PASS/$total passed${RESET}"
        return 0
    else
        echo -e "  ${RED}${BOLD}$PASS/$total passed, $FAIL failed${RESET}"
        return 1
    fi
}

# ── Assertions ────────────────────────────────────────────────────────────────

# assert_eq LABEL EXPECTED ACTUAL
assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label (expected: '$expected', got: '$actual')"
    fi
}

# assert_contains LABEL NEEDLE HAYSTACK
assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label (expected to contain: '$needle')"
        echo "    haystack: $haystack" >&2
    fi
}

# assert_not_contains LABEL NEEDLE HAYSTACK
assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    if ! echo "$haystack" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label (expected NOT to contain: '$needle')"
    fi
}

# assert_exits_nonzero LABEL CMD...
assert_exits_nonzero() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$label (expected non-zero exit, got 0)"
    else
        pass "$label"
    fi
}

# assert_exits_zero LABEL CMD...
assert_exits_zero() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label (expected exit 0, command failed)"
    fi
}

# assert_file_contains LABEL FILE NEEDLE
assert_file_contains() {
    local label="$1" file="$2" needle="$3"
    if grep -qF "$needle" "$file" 2>/dev/null; then
        pass "$label"
    else
        fail "$label (file '$file' does not contain '$needle')"
    fi
}

# assert_json_field LABEL FILE JQPATH EXPECTED
assert_json_field() {
    local label="$1" file="$2" jqpath="$3" expected="$4"
    local actual
    actual=$(jq -r "$jqpath" "$file" 2>/dev/null || echo "JQ_ERROR")
    assert_eq "$label" "$expected" "$actual"
}

# ── Vault helpers ─────────────────────────────────────────────────────────────

# setup_user NAME VAULT_DIR
# Creates ~/.aman/<name>.key and <vault_dir>/<name>.pub, registers in vault.
# Requires AMAN_PASSPHRASE to be set.
setup_user() {
    local name="$1" vault_dir="$2"
    local pub_file="$vault_dir/${name}.pub"
    HOME_FOR_USER="/tmp/homes/$name"
    mkdir -p "$HOME_FOR_USER"
    AMAN_IDENTITY="$name" HOME="$HOME_FOR_USER" \
        aman keygen --name "$name" --out "$vault_dir" >/dev/null 2>&1
    HOME="$HOME_FOR_USER" \
        aman --vault "$vault_dir" member add "$name" "$pub_file" --yes >/dev/null 2>&1
}

# as_user NAME VAULT_DIR CMD...
# Runs an aman command as a given user (sets HOME and AMAN_IDENTITY).
as_user() {
    local name="$1" vault_dir="$2"
    shift 2
    AMAN_IDENTITY="$name" HOME="/tmp/homes/$name" \
        aman --vault "$vault_dir" "$@"
}
