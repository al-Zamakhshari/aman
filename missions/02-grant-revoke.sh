#!/usr/bin/env bash
# Mission 02: Multi-user grant and revoke
# Alice adds a secret, grants Bob access, Bob reads it, then Alice revokes
# Bob — Bob can no longer decrypt but Alice still can.
# Carol is never granted access and is always denied.
set -euo pipefail
source /missions/lib.sh

mission_start "02 · Grant / revoke multi-user flow"

VAULT=$(mktemp -d)
trap 'rm -rf "$VAULT" /tmp/homes/alice /tmp/homes/bob /tmp/homes/carol' EXIT

# ── Setup ─────────────────────────────────────────────────────────────────────

aman init "$VAULT" --name acme-vault >/dev/null 2>&1
setup_user alice "$VAULT"
setup_user bob   "$VAULT"
setup_user carol "$VAULT"

# ── Add (alice only) ──────────────────────────────────────────────────────────

as_user alice "$VAULT" add prod-db \
    --to alice \
    --password "db-pass-xyz" >/dev/null 2>&1
pass "add secret for alice-only"

# ── Bob denied before grant ───────────────────────────────────────────────────

assert_exits_nonzero "bob denied before grant" \
    as_user bob "$VAULT" get prod-db --no-clipboard

# ── Carol always denied ───────────────────────────────────────────────────────

assert_exits_nonzero "carol denied (never granted)" \
    as_user carol "$VAULT" get prod-db --no-clipboard

# ── Alice grants Bob ──────────────────────────────────────────────────────────

grant_out=$(as_user alice "$VAULT" grant prod-db --to bob --yes 2>&1)
assert_contains "grant succeeds" "✓" "$grant_out"

# ── Bob can now decrypt ───────────────────────────────────────────────────────

bob_got=$(as_user bob "$VAULT" get prod-db --no-clipboard --field password 2>&1)
assert_eq "bob reads correct password after grant" "db-pass-xyz" "$bob_got"

# ── Alice can still decrypt after grant ───────────────────────────────────────

alice_got=$(as_user alice "$VAULT" get prod-db --no-clipboard --field password 2>&1)
assert_eq "alice reads correct password after grant" "db-pass-xyz" "$alice_got"

# ── Carol still denied after grant to bob ─────────────────────────────────────

assert_exits_nonzero "carol still denied after bob's grant" \
    as_user carol "$VAULT" get prod-db --no-clipboard

# ── Alice revokes Bob ─────────────────────────────────────────────────────────

revoke_out=$(as_user alice "$VAULT" revoke prod-db --from bob 2>&1)
assert_contains "revoke succeeds" "✓" "$revoke_out"

# ── Bob denied after revoke (new FEK) ─────────────────────────────────────────

assert_exits_nonzero "bob denied after revoke" \
    as_user bob "$VAULT" get prod-db --no-clipboard

# ── Alice still decrypts after revoke ────────────────────────────────────────

alice_after=$(as_user alice "$VAULT" get prod-db --no-clipboard --field password 2>&1)
assert_eq "alice reads correct password after revoke" "db-pass-xyz" "$alice_after"

# ── Verify signature still valid after revoke ────────────────────────────────

verify_out=$(as_user alice "$VAULT" verify prod-db 2>&1)
assert_contains "signature valid after revoke" "✓" "$verify_out"

mission_end
