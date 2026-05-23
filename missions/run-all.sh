#!/usr/bin/env bash
# run-all.sh — Execute all aman mission tests and report results.
# Exit code 0 only if every mission passes.
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

MISSIONS=(
    /missions/01-basic-flow.sh
    /missions/02-grant-revoke.sh
    /missions/03-shamir-threshold.sh
    /missions/04-tamper-detection.sh
    /missions/05-path-traversal.sh
    /missions/06-import-export.sh
)

PASSED=0
FAILED=0
FAILED_NAMES=()

echo ""
echo -e "${BOLD}▶ aman mission tests${RESET}"
echo "  binary: $(aman --version 2>&1 || echo 'unknown')"
echo "  date  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

for mission in "${MISSIONS[@]}"; do
    name=$(basename "$mission")
    if bash "$mission"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_NAMES+=("$name")
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOTAL=$((PASSED + FAILED))
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ALL $TOTAL missions passed ✓${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}  $PASSED/$TOTAL missions passed, $FAILED failed:${RESET}"
    for n in "${FAILED_NAMES[@]}"; do
        echo -e "  ${RED}✗${RESET} $n"
    done
    exit 1
fi
