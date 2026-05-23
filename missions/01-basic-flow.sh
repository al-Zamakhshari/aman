#!/usr/bin/env bash
# Mission 01: Basic single-user flow
# Alice generates a key, creates a vault, adds a secret, reads it back,
# lists entries, and exports to both supported formats.
set -euo pipefail
source /missions/lib.sh

mission_start "01 · Basic single-user flow"

VAULT=$(mktemp -d)
trap 'rm -rf "$VAULT" /tmp/homes/alice' EXIT

# ── Setup ─────────────────────────────────────────────────────────────────────

aman init "$VAULT" --name acme-vault >/dev/null 2>&1
setup_user alice "$VAULT"

# ── Add ───────────────────────────────────────────────────────────────────────

out=$(as_user alice "$VAULT" add github \
    --to alice \
    --user "deploy@acme.com" \
    --url "https://github.com" \
    --notes "main deploy token" \
    --password "s3cr3t-hunter2" 2>&1)
assert_contains "add succeeds" "✓ Secret" "$out"

# ── Get ───────────────────────────────────────────────────────────────────────

got=$(as_user alice "$VAULT" get github --no-clipboard --field password 2>&1)
assert_eq "get returns correct password" "s3cr3t-hunter2" "$got"

got_user=$(as_user alice "$VAULT" get github --no-clipboard --field user 2>&1)
assert_eq "get returns correct username" "deploy@acme.com" "$got_user"

got_url=$(as_user alice "$VAULT" get github --no-clipboard --field url 2>&1)
assert_eq "get returns correct URL" "https://github.com" "$got_url"

# ── List ──────────────────────────────────────────────────────────────────────

list_out=$(as_user alice "$VAULT" list 2>&1)
assert_contains "list shows entry" "github" "$list_out"

# ── Verify ────────────────────────────────────────────────────────────────────

verify_out=$(as_user alice "$VAULT" verify github 2>&1)
assert_contains "verify passes" "✓" "$verify_out"

# ── Export: bitwarden ─────────────────────────────────────────────────────────

bw_file="$VAULT/export.json"
as_user alice "$VAULT" export --format bitwarden --out "$bw_file" >/dev/null 2>&1
assert_json_field "bitwarden export: encrypted=false" "$bw_file" ".encrypted" "false"
assert_json_field "bitwarden export: entry name" "$bw_file" ".items[0].name" "github"
assert_json_field "bitwarden export: username" "$bw_file" ".items[0].login.username" "deploy@acme.com"

# ── Export: CSV ───────────────────────────────────────────────────────────────

csv_file="$VAULT/export.csv"
as_user alice "$VAULT" export --format csv --out "$csv_file" >/dev/null 2>&1
assert_file_contains "CSV export contains entry name" "$csv_file" "github"
assert_file_contains "CSV export contains username" "$csv_file" "deploy@acme.com"
assert_file_contains "CSV export contains password" "$csv_file" "s3cr3t-hunter2"

# ── Non-existent entry ────────────────────────────────────────────────────────

assert_exits_nonzero "get non-existent fails" \
    as_user alice "$VAULT" get doesnotexist --no-clipboard

mission_end
