#!/usr/bin/env bash
# Mission 03: Shamir M-of-N threshold encryption
# A 3-of-5 secret is created. Tests:
#   • Any single holder cannot decrypt alone
#   • 2 shares are insufficient
#   • Exactly 3 shares reconstruct the secret
#   • Expired share files are rejected
set -euo pipefail
source /missions/lib.sh

mission_start "03 · Shamir 3-of-5 threshold"

VAULT=$(mktemp -d)
SHARES_DIR=$(mktemp -d)
trap 'rm -rf "$VAULT" "$SHARES_DIR" /tmp/homes/alice /tmp/homes/bob /tmp/homes/carol /tmp/homes/dave /tmp/homes/eve' EXIT

# ── Setup: 5 users ────────────────────────────────────────────────────────────

aman init "$VAULT" --name secrets-vault >/dev/null 2>&1
for user in alice bob carol dave eve; do
    setup_user "$user" "$VAULT"
done

# ── Add a 3-of-5 threshold secret ────────────────────────────────────────────

add_out=$(as_user alice "$VAULT" add nuclear-codes \
    --to alice,bob,carol,dave,eve \
    --threshold 3 \
    --password "launch-code-alpha-7" 2>&1)
assert_contains "threshold add succeeds" "✓" "$add_out"

# ── Single recipient cannot use 'get' directly ────────────────────────────────

assert_exits_nonzero "single recipient blocked from direct get" \
    as_user alice "$VAULT" get nuclear-codes --no-clipboard

# ── Each user collects their share ────────────────────────────────────────────

for user in alice bob carol dave eve; do
    share_out=$(as_user "$user" "$VAULT" collect nuclear-codes \
        --out "$SHARES_DIR/${user}.share" \
        --ttl 1h 2>&1)
    assert_contains "collect: $user saves share" "✓" "$share_out"
done

# ── 2 shares are not enough ───────────────────────────────────────────────────

assert_exits_nonzero "2 shares insufficient (need 3)" \
    as_user alice "$VAULT" get nuclear-codes --no-clipboard \
        --shares "$SHARES_DIR/bob.share,$SHARES_DIR/carol.share"

# ── 3 shares reconstruct the secret ──────────────────────────────────────────

got=$(as_user alice "$VAULT" get nuclear-codes --no-clipboard --field password \
    --shares "$SHARES_DIR/bob.share,$SHARES_DIR/carol.share,$SHARES_DIR/dave.share" 2>&1)
assert_eq "3 shares reconstruct correct secret" "launch-code-alpha-7" "$got"

# ── Any 3 of the 5 work (different combination) ───────────────────────────────

got2=$(as_user alice "$VAULT" get nuclear-codes --no-clipboard --field password \
    --shares "$SHARES_DIR/alice.share,$SHARES_DIR/eve.share,$SHARES_DIR/dave.share" 2>&1)
assert_eq "different 3-share combo also works" "launch-code-alpha-7" "$got2"

# ── All 5 shares also work ────────────────────────────────────────────────────

all_shares=$(ls "$SHARES_DIR"/*.share | tr '\n' ',' | sed 's/,$//')
got3=$(as_user alice "$VAULT" get nuclear-codes --no-clipboard --field password \
    --shares "$all_shares" 2>&1)
assert_eq "all 5 shares work" "launch-code-alpha-7" "$got3"

# ── Expired share is rejected ────────────────────────────────────────────────
# Collect a share with a tiny TTL, wait, then try to use it.
# We manufacture an expired share file directly (no sleep in tests).

expired_share="$SHARES_DIR/expired.share"
# Copy alice's valid share and patch the expires_at to be in the past.
jq '.expires_at = "2000-01-01T00:00:00Z"' "$SHARES_DIR/alice.share" > "$expired_share"

assert_exits_nonzero "expired share rejected" \
    as_user alice "$VAULT" get nuclear-codes --no-clipboard \
        --shares "$expired_share,$SHARES_DIR/bob.share,$SHARES_DIR/carol.share"

# ── Share bound to wrong vault is rejected ────────────────────────────────────

wrong_vault_share="$SHARES_DIR/wrong-vault.share"
jq '.vault = "evil-vault"' "$SHARES_DIR/alice.share" > "$wrong_vault_share"

assert_exits_nonzero "wrong-vault share rejected" \
    as_user alice "$VAULT" get nuclear-codes --no-clipboard \
        --shares "$wrong_vault_share,$SHARES_DIR/bob.share,$SHARES_DIR/carol.share"

# ── Share bound to wrong entry is rejected ────────────────────────────────────

wrong_entry_share="$SHARES_DIR/wrong-entry.share"
jq '.entry = "other-secret"' "$SHARES_DIR/alice.share" > "$wrong_entry_share"

assert_exits_nonzero "wrong-entry share rejected" \
    as_user alice "$VAULT" get nuclear-codes --no-clipboard \
        --shares "$wrong_entry_share,$SHARES_DIR/bob.share,$SHARES_DIR/carol.share"

mission_end
