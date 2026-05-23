#!/usr/bin/env bash
# Mission 06: Bitwarden import and round-trip export
# Seeds the vault by importing a Bitwarden JSON file, then verifies
# the entries are readable and re-exportable as CSV.
set -euo pipefail
source /missions/lib.sh

mission_start "06 · Bitwarden import → aman → CSV export"

VAULT=$(mktemp -d)
trap 'rm -rf "$VAULT" /tmp/homes/alice' EXIT

aman init "$VAULT" --name import-vault >/dev/null 2>&1
setup_user alice "$VAULT"

# ── Write a minimal Bitwarden export to import ────────────────────────────────

BW_FILE="$VAULT/bw-import.json"
cat > "$BW_FILE" <<'JSON'
{
  "encrypted": false,
  "items": [
    {
      "type": 1,
      "name": "github",
      "notes": "main repo",
      "login": {
        "username": "deploy@acme.com",
        "password": "gh-token-abc123",
        "uris": [{ "uri": "https://github.com" }]
      }
    },
    {
      "type": 1,
      "name": "stripe-live",
      "notes": "",
      "login": {
        "username": "",
        "password": "sk_live_xyz789",
        "uris": []
      }
    }
  ]
}
JSON

# ── Import ────────────────────────────────────────────────────────────────────

import_out=$(as_user alice "$VAULT" import "$BW_FILE" --to alice 2>&1)
assert_contains "import: reports completion" "Import complete" "$import_out"
assert_contains "import: mentions github" "github" "$import_out"
assert_contains "import: mentions stripe-live" "stripe-live" "$import_out"

# ── Read back individual fields ───────────────────────────────────────────────

gh_pass=$(as_user alice "$VAULT" get github --no-clipboard --field password 2>&1)
assert_eq "import: github password correct" "gh-token-abc123" "$gh_pass"

gh_user=$(as_user alice "$VAULT" get github --no-clipboard --field user 2>&1)
assert_eq "import: github username correct" "deploy@acme.com" "$gh_user"

stripe_pass=$(as_user alice "$VAULT" get stripe-live --no-clipboard --field password 2>&1)
assert_eq "import: stripe-live password correct" "sk_live_xyz789" "$stripe_pass"

# ── Export back to bitwarden ──────────────────────────────────────────────────

BW_OUT="$VAULT/bw-roundtrip.json"
as_user alice "$VAULT" export --format bitwarden --out "$BW_OUT" >/dev/null 2>&1

assert_json_field "roundtrip: encrypted=false" "$BW_OUT" ".encrypted" "false"
gh_name=$(jq -r '[.items[] | select(.name=="github")] | .[0].name' "$BW_OUT")
assert_eq "roundtrip: github entry present" "github" "$gh_name"

stripe_name=$(jq -r '[.items[] | select(.name=="stripe-live")] | .[0].name' "$BW_OUT")
assert_eq "roundtrip: stripe-live entry present" "stripe-live" "$stripe_name"

# ── Export to CSV ─────────────────────────────────────────────────────────────

CSV_OUT="$VAULT/export.csv"
as_user alice "$VAULT" export --format csv --out "$CSV_OUT" >/dev/null 2>&1
assert_file_contains "CSV: github row present" "$CSV_OUT" "github"
assert_file_contains "CSV: stripe-live row present" "$CSV_OUT" "stripe-live"
assert_file_contains "CSV: github password in CSV" "$CSV_OUT" "gh-token-abc123"

mission_end
