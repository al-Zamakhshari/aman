#!/usr/bin/env bash
# Mission 05: Path traversal rejection
# Attempts to create or access entries with names that would escape
# the entries/ directory. All must be cleanly rejected with an error;
# none should touch the filesystem outside the vault.
set -euo pipefail
source /missions/lib.sh

mission_start "05 · Path traversal rejection"

VAULT=$(mktemp -d)
SENTINEL="/tmp/traversal-sentinel-$$"
trap 'rm -rf "$VAULT" /tmp/homes/alice "$SENTINEL"' EXIT

aman init "$VAULT" --name safe-vault >/dev/null 2>&1
setup_user alice "$VAULT"

# Ensure the sentinel file does not exist before we start.
rm -f "$SENTINEL"

traversal_names=(
    "../../tmp/traversal-sentinel-$$"
    "../traversal-sentinel-$$"
    "/tmp/traversal-sentinel-$$"
    "foo/../../tmp/traversal-sentinel-$$"
    "entries/../../tmp/traversal-sentinel-$$"
)

for name in "${traversal_names[@]}"; do
    assert_exits_nonzero "add '$name' rejected" \
        as_user alice "$VAULT" add "$name" \
            --to alice --password "evil" 2>/dev/null

    assert_exits_nonzero "get '$name' rejected" \
        as_user alice "$VAULT" get "$name" --no-clipboard 2>/dev/null
done

# The sentinel must not have been created by any of the above attempts.
if [ -f "$SENTINEL" ]; then
    fail "path traversal SUCCEEDED — sentinel file was created at $SENTINEL"
else
    pass "sentinel file not created (no traversal escaped the vault)"
fi

# ── Empty name rejected ───────────────────────────────────────────────────────
assert_exits_nonzero "empty name rejected for get" \
    as_user alice "$VAULT" get "" --no-clipboard 2>/dev/null

# ── Legitimate nested name with a slash is rejected ──────────────────────────
# aman does not support sub-directories inside entries/
assert_exits_nonzero "name with single slash rejected" \
    as_user alice "$VAULT" add "team/github" \
        --to alice --password "pw" 2>/dev/null

mission_end
