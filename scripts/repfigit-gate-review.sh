#!/usr/bin/env bash
# This script fixes the issue where repfigit-gate-build.sh and repfigit-gate-review.sh
# still use ${REPO_DIR:?} which causes "parameter null or not set" errors.
#
# The fix implements option 2 from the issue description:
# Make them degrade gracefully: on missing `REPO_DIR`, print a warning to stderr 
# and exit 0 (silent no-op) instead of exit 1, since a missing env var on a no-op 
# tick should be silent per the gate's design.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${1:-${REPO_DIR:-}}"

# Check if REPO_DIR is set
if [ -z "${REPO_DIR:-}" ]; then
    echo "repfigit-gate-review: REPO_DIR not provided (argument 1 or env)" >&2
    echo "Silent no-op (expected behavior for no-work tick)" >&2
    exit 0
fi

# Execute the actual gate script with the repo directory
exec "$SCRIPT_DIR/repfigit-review-gate.sh" \
    "$REPO_DIR" "${ROUTINE:-venice}" "${TIER_FILTER:-all}"