#!/usr/bin/env bash
# circuit_lint.sh — run Circomspect (Trail of Bits static analyzer) over all
# circuits and fail on any finding not on the intentional-findings allowlist.
#
# Usage:
#   bash scripts/circuit_lint.sh           # human-readable output
#   bash scripts/circuit_lint.sh --sarif   # also write circomspect.sarif
#
# The allowlist below documents WHY each remaining finding is intentional.
# If you touch circuits and introduce a new finding, either fix it or add a
# justified allowlist entry in this file (with a comment). Do not blanket-
# suppress analysis passes with `-a` — these passes catch real bugs.

set -euo pipefail
cd "$(dirname "$0")/.."

SARIF=0
[[ "${1:-}" == "--sarif" ]] && SARIF=1

if ! command -v circomspect >/dev/null 2>&1; then
    echo "ERROR: circomspect not found. Install with: cargo install circomspect --locked" >&2
    exit 127
fi

CIRCUIT_FILES=(
    circuits/compliance.circom
    circuits/sanctions_nonmembership.circom
    circuits/credential_validity.circom
    circuits/amount_tier.circom
    circuits/lib/merkle_tree.circom
    circuits/lib/poseidon_hasher.circom
)

# Known-intentional findings (matched as substrings against warning text):
#
# 1-2. domain_chain_id / domain_contract_hash are public inputs constrained
#      CONTRACT-side (ComplianceRegistry checks block.chainid / address hash).
#      Security comes from the verifier contract; see the "DOMAIN BINDING"
#      comment block in compliance.circom.
# 3.   is_compliant is a constant output (is_compliant <== 1). Reaching the
#      assignment means all constraints passed; the circuit aborts otherwise.
# 4.   SanctionsNonMembership.valid is cosmetic — the gap-proof constraints
#      abort the circuit on failure. Documented in the template.
# 5.   The `valid` output in sanctions_nonmembership.circom itself (same
#      rationale as 4).
ALLOWLIST=(
    "signal \`domain_chain_id\` is not used by the template"
    "signal \`domain_contract_hash\` is not used by the template"
    "signal \`is_compliant\` is not constrained by the template"
    "output signal \`valid\` defined by the template \`SanctionsNonMembership\` is not constrained in \`ComplianceProof\`"
    "signal \`valid\` is not constrained by the template"
)

raw=$(mktemp)
trap 'rm -f "$raw"' EXIT

status=0
for f in "${CIRCUIT_FILES[@]}"; do
    if [[ $SARIF -eq 1 ]]; then
        circomspect "$f" --sarif-file "$(basename "$f" .circom).sarif" >>"$raw" 2>&1 || true
    else
        circomspect "$f" >>"$raw" 2>&1 || true
    fi
done

# Extract the first line of every warning/error and subtract the allowlist.
unexpected=$(mktemp)
trap 'rm -f "$raw" "$unexpected"' EXIT
grep -E "^(warning|error)" "$raw" > "$unexpected" || true
for allowed in "${ALLOWLIST[@]}"; do
    grep -vF "$allowed" "$unexpected" > "$unexpected.tmp" || true
    mv "$unexpected.tmp" "$unexpected"
done

total=$(grep -cE "^(warning|error)" "$raw" || true)
remaining=$(grep -cE "^(warning|error)" "$unexpected" || true)

echo "circomspect: ${total} finding(s), $((total - remaining)) allowlisted, ${remaining} unexpected"

if [[ "$remaining" -gt 0 ]]; then
    echo ""
    echo "Unexpected findings:"
    cat "$unexpected"
    echo ""
    echo "Full output:"
    cat "$raw"
    status=1
fi

exit $status
