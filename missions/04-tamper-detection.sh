#!/usr/bin/env bash
# Mission 04: Tamper detection
# Verifies that aman rejects entries whose on-disk JSON has been mutated:
#   • Flipped ciphertext byte → sig check fails (ciphertext is in signable)
#   • Replaced signature bytes → sig check fails
#   • Modified recipient list → sig check fails
#   • Modified name field → sig check fails
#   • Unmodified entry → passes cleanly
set -euo pipefail
source /missions/lib.sh

mission_start "04 · Tamper detection"

VAULT=$(mktemp -d)
trap 'rm -rf "$VAULT" /tmp/homes/alice' EXIT

aman init "$VAULT" --name secure-vault >/dev/null 2>&1
setup_user alice "$VAULT"

as_user alice "$VAULT" add api-key \
    --to alice \
    --password "real-api-key-abc123" >/dev/null 2>&1

ENC_FILE="$VAULT/entries/api-key.enc"

# ── Baseline: verify and get work on untampered entry ────────────────────────

verify_out=$(as_user alice "$VAULT" verify api-key 2>&1)
assert_contains "baseline: verify passes" "✓" "$verify_out"

baseline_got=$(as_user alice "$VAULT" get api-key --no-clipboard --field password 2>&1)
assert_eq "baseline: get returns correct value" "real-api-key-abc123" "$baseline_got"

# ── Helper: make a backup of the real entry ───────────────────────────────────
cp "$ENC_FILE" "${ENC_FILE}.orig"

restore_entry() {
    cp "${ENC_FILE}.orig" "$ENC_FILE"
}

# ── Tamper 1: flip a byte in the ciphertext ───────────────────────────────────
# jq encodes ciphertext as base64 — we flip the last char of the b64 string.
jq '.ciphertext = (.ciphertext | if . == null then null else (.[:-1] + (if (.[-1:] == "A") then "B" else "A" end)) end)' \
    "$ENC_FILE" > "${ENC_FILE}.tmp" && mv "${ENC_FILE}.tmp" "$ENC_FILE"

assert_exits_nonzero "tampered ciphertext: verify fails" \
    as_user alice "$VAULT" verify api-key
assert_exits_nonzero "tampered ciphertext: get fails" \
    as_user alice "$VAULT" get api-key --no-clipboard

restore_entry

# ── Tamper 2: zero out the signature ─────────────────────────────────────────
jq '.signature = ""' "$ENC_FILE" > "${ENC_FILE}.tmp" && mv "${ENC_FILE}.tmp" "$ENC_FILE"

assert_exits_nonzero "zeroed signature: verify fails" \
    as_user alice "$VAULT" verify api-key
assert_exits_nonzero "zeroed signature: get fails" \
    as_user alice "$VAULT" get api-key --no-clipboard

restore_entry

# ── Tamper 3: modify the name field ──────────────────────────────────────────
jq '.name = "evil-key"' "$ENC_FILE" > "${ENC_FILE}.tmp" && mv "${ENC_FILE}.tmp" "$ENC_FILE"

assert_exits_nonzero "modified name: verify fails" \
    as_user alice "$VAULT" verify api-key
# (get uses the filename-derived name, not the JSON name, so sig still checked)

restore_entry

# ── Tamper 4: add a fake recipient ────────────────────────────────────────────
jq '.recipients += ["mallory"]' "$ENC_FILE" > "${ENC_FILE}.tmp" && mv "${ENC_FILE}.tmp" "$ENC_FILE"

assert_exits_nonzero "injected recipient: verify fails" \
    as_user alice "$VAULT" verify api-key
assert_exits_nonzero "injected recipient: get fails" \
    as_user alice "$VAULT" get api-key --no-clipboard

restore_entry

# ── Tamper 5: downgrade version field ─────────────────────────────────────────
jq '.version = 1' "$ENC_FILE" > "${ENC_FILE}.tmp" && mv "${ENC_FILE}.tmp" "$ENC_FILE"

# v1 entries use a different signable (no UpdatedAt) — sig will mismatch
assert_exits_nonzero "version downgrade: verify fails" \
    as_user alice "$VAULT" verify api-key
assert_exits_nonzero "version downgrade: get fails" \
    as_user alice "$VAULT" get api-key --no-clipboard

restore_entry

# ── Verify --all on multiple entries ─────────────────────────────────────────
as_user alice "$VAULT" add second-key \
    --to alice --password "pw2" >/dev/null 2>&1

verify_all_out=$(as_user alice "$VAULT" verify --all 2>&1)
assert_contains "verify --all: api-key passes" "api-key" "$verify_all_out"
assert_contains "verify --all: second-key passes" "second-key" "$verify_all_out"

mission_end
