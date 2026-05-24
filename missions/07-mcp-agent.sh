#!/usr/bin/env bash
# Mission 07: MCP server — AI agent credential access
#
# Verifies that `aman mcp` correctly:
#   - Refuses to start without AMAN_PASSPHRASE
#   - Exposes list_credentials, get_credential, check_access over stdio
#   - Enforces identity-scoped access (bob cannot get alice's secret)
#   - Returns deliberately vague errors on access denial
#   - Records every get in the audit log
set -euo pipefail
source /missions/lib.sh

mission_start "07 · MCP server — AI agent credential access"

VAULT=$(mktemp -d)
trap 'rm -rf "$VAULT" /tmp/homes/alice /tmp/homes/bob' EXIT

# ── Setup: vault + two users ───────────────────────────────────────────────────

aman init "$VAULT" --name mcp-vault >/dev/null 2>&1
setup_user alice "$VAULT"
setup_user bob   "$VAULT"

as_user alice "$VAULT" add github \
    --to alice \
    --user "deploy@acme.com" \
    --url  "https://github.com" \
    --notes "main deploy token" \
    --password "s3cr3t-hunter2" >/dev/null 2>&1

as_user alice "$VAULT" add stripe \
    --to alice \
    --user "billing@acme.com" \
    --password "sk_live_abc123" \
    --tag prod >/dev/null 2>&1

pass "setup: vault, users, and credentials created"

# ── MCP helper ────────────────────────────────────────────────────────────────
#
# mcp_call NAME VAULT_DIR TOOL [ARGS_JSON]
# Spawns `aman mcp` as NAME, sends one tool call over stdin (JSON-RPC 2.0),
# captures and returns the tool result as a JSON string.
# The server exits when stdin reaches EOF.
mcp_call() {
    local name="$1" vault_dir="$2" tool="$3" args="${4:-{}}"
    {
        printf '%s\n' \
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mission-test","version":"1.0"}}}' \
            '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
            '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"'"$tool"'","arguments":'"$args"'}}'
    } | timeout 10 \
        AMAN_IDENTITY="$name" HOME="/tmp/homes/$name" \
        aman --vault "$vault_dir" mcp 2>/dev/null \
      | jq -r 'select(.id == 2) | .result.content[0].text' 2>/dev/null
}

# ── 1. Refuses to start without AMAN_PASSPHRASE ───────────────────────────────

unset AMAN_PASSPHRASE
assert_exits_nonzero "mcp: refuses to start without AMAN_PASSPHRASE" \
    bash -c "AMAN_IDENTITY=alice HOME=/tmp/homes/alice aman --vault '$VAULT' mcp </dev/null"
export AMAN_PASSPHRASE=mission-test-passphrase

# ── 2. list_credentials — returns alice's entries ─────────────────────────────

list_out=$(mcp_call alice "$VAULT" list_credentials '{}')
assert_contains "list_credentials: returns JSON"          "credentials" "$list_out"
assert_contains "list_credentials: github entry present"  "github"      "$list_out"
assert_contains "list_credentials: stripe entry present"  "stripe"      "$list_out"
assert_contains "list_credentials: identity field"        "alice"       "$list_out"

count=$(printf '%s' "$list_out" | jq '.count' 2>/dev/null || echo 0)
assert_eq "list_credentials: count is 2" "2" "$count"

# ── 3. list_credentials — tag filter ──────────────────────────────────────────

tagged_out=$(mcp_call alice "$VAULT" list_credentials '{"tag":"prod"}')
assert_contains     "list_credentials: tag=prod returns stripe" "stripe" "$tagged_out"
assert_not_contains "list_credentials: tag=prod excludes github" "github" "$tagged_out"

tagged_count=$(printf '%s' "$tagged_out" | jq '.count' 2>/dev/null || echo 0)
assert_eq "list_credentials: tag=prod count is 1" "1" "$tagged_count"

# ── 4. get_credential — correct password ──────────────────────────────────────

get_out=$(mcp_call alice "$VAULT" get_credential '{"name":"github","field":"password"}')
assert_contains "get_credential: returns value key"   '"value"'         "$get_out"
assert_contains "get_credential: correct password"    "s3cr3t-hunter2"  "$get_out"
assert_contains "get_credential: security warning"    "_warning"        "$get_out"

# ── 5. get_credential — correct username ──────────────────────────────────────

user_out=$(mcp_call alice "$VAULT" get_credential '{"name":"github","field":"user"}')
assert_contains "get_credential: correct username" "deploy@acme.com" "$user_out"

# ── 6. get_credential — URL field ─────────────────────────────────────────────

url_out=$(mcp_call alice "$VAULT" get_credential '{"name":"github","field":"url"}')
assert_contains "get_credential: correct url" "https://github.com" "$url_out"

# ── 7. get_credential — nonexistent entry is vague ────────────────────────────
# Error must say "access denied" and must NOT distinguish "entry missing" from
# "no recipient block" — either disclosure leaks the vault's inventory.

denied_out=$(mcp_call alice "$VAULT" get_credential '{"name":"does-not-exist","field":"password"}')
assert_contains     "get_credential: vague error — says access denied" "access denied" "$denied_out"
assert_not_contains "get_credential: vague error — no 'not found'"     "not found"     "$denied_out"
assert_not_contains "get_credential: vague error — no credential value" '"value"'      "$denied_out"

# ── 8. get_credential — unknown field returns error ───────────────────────────

bad_field_out=$(mcp_call alice "$VAULT" get_credential '{"name":"github","field":"credit_card"}')
assert_contains "get_credential: unknown field error" "unknown field" "$bad_field_out"

# ── 9. check_access — accessible entry ───────────────────────────────────────

check_yes=$(mcp_call alice "$VAULT" check_access '{"name":"github"}')
accessible=$(printf '%s' "$check_yes" | jq '.accessible' 2>/dev/null || echo "null")
assert_eq "check_access: github accessible to alice" "true" "$accessible"

# ── 10. check_access — nonexistent entry ─────────────────────────────────────

check_no=$(mcp_call alice "$VAULT" check_access '{"name":"no-such-entry"}')
accessible_no=$(printf '%s' "$check_no" | jq '.accessible' 2>/dev/null || echo "null")
assert_eq "check_access: nonexistent entry not accessible" "false" "$accessible_no"

# ── 11. Bob cannot get alice's credentials ────────────────────────────────────

bob_list=$(mcp_call bob "$VAULT" list_credentials '{}')
bob_count=$(printf '%s' "$bob_list" | jq '.count' 2>/dev/null || echo 0)
assert_eq "list_credentials: bob sees 0 credentials" "0" "$bob_count"

bob_denied=$(mcp_call bob "$VAULT" get_credential '{"name":"github","field":"password"}')
assert_contains "get_credential: bob denied access to alice's github" "access denied" "$bob_denied"
assert_not_contains "get_credential: bob does not see the password" "s3cr3t-hunter2" "$bob_denied"

# ── 12. Audit log records get operations ──────────────────────────────────────

audit_log="$VAULT/audit.log"
assert_file_contains "audit: get for github recorded" "$audit_log" "github"
assert_file_contains "audit: actor is alice"          "$audit_log" "alice"

mission_end
