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
    circuits/wallet_ownership_credential.circom
    circuits/compliance.circom
    circuits/sanctions_nonmembership.circom
    circuits/credential_validity.circom
    circuits/amount_tier.circom
    circuits/lib/merkle_tree.circom
    circuits/lib/poseidon_hasher.circom
    # Current profile (pilot-transfer-v3). Circomspect analyzes only the
    # templates defined in the file it is given, so every file is listed.
    circuits/pilot_compliance.circom
    circuits/pilot_transfer.circom
    circuits/pilot_credential.circom
    circuits/pilot_sanctions.circom
    circuits/pilot_valuation.circom
    circuits/generated/pilot_constants.circom
    circuits/generated/pilot_main.circom
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

# Per-file findings with an exact expected count: "file|count|message substring".
#
# These warning types are generic ("Inputs to `LessThan` ..."), so a blanket
# substring entry would also hide a new, real instance. Each entry therefore
# names one file and the exact number of occurrences reviewed there. A new
# occurrence, or one that disappears, fails the gate until this list is
# re-reviewed. Circomspect checks one template at a time and does not follow a
# signal into another template or through a loop, which is why these remain.
#
# pilot_compliance.circom (1):
#   `fresh.in[0] <== evaluated_at`. evaluated_at === transfer_fields[23], which
#   PilotTransferProjection range-checks to 53 bits (PilotProjectionWidth(23)).
# pilot_transfer.circom (2 + 1):
#   `unexpired.in[0..1]` are transfer_fields[23] and [22]; both are 53-bit
#   range-checked by the `ranges` loop in the same template.
#   `Num2Bits(PilotProjectionWidth(i))`: the widest field is 160 bits, below
#   the 254-bit field size, so the non-strict conversion cannot alias.
# pilot_valuation.circom (3 + 7):
#   `remainder_bound.in[1] <== denominator`: denominator is 128-bit
#   range-checked as `quotient_product.b` inside PilotMultiply128.
#   `ordered[i].in[0..1]` are thresholds[i], each 128-bit range-checked by the
#   `ranges` loop in PilotAmountTier.
#   `<--` (7): every hinted limb or carry is fixed by a decomposition
#   constraint on the next line and range-checked (64-bit limbs, 64/65-bit
#   carries in PilotMultiply128; boolean carries in PilotValuation). All sums
#   stay below 2^130, so no constraint wraps the field and each decomposition
#   is unique.
COUNTED_ALLOWLIST=(
    "circuits/pilot_compliance.circom|1|Inputs to \`LessThan\` need to be constrained to ensure that they are non-negative"
    "circuits/pilot_transfer.circom|2|Inputs to \`LessThan\` need to be constrained to ensure that they are non-negative"
    "circuits/pilot_transfer.circom|1|Using \`Num2Bits\` to convert field elements to bits may lead to aliasing issues"
    "circuits/pilot_valuation.circom|3|Inputs to \`LessThan\` need to be constrained to ensure that they are non-negative"
    "circuits/pilot_valuation.circom|7|Using the signal assignment operator \`<--\` does not constrain the assigned signal"
)

raw=$(mktemp)
current=$(mktemp)
findings=$(mktemp)
unexpected=$(mktemp)
mismatch=$(mktemp)
trap 'rm -f "$raw" "$current" "$findings" "$findings.tmp" "$unexpected" "$unexpected.tmp" "$mismatch"' EXIT

status=0
total=0
for f in "${CIRCUIT_FILES[@]}"; do
    analyzer_status=0
    if [[ $SARIF -eq 1 ]]; then
        circomspect "$f" --sarif-file "$(basename "$f" .circom).sarif" >"$current" 2>&1 || analyzer_status=$?
    else
        circomspect "$f" >"$current" 2>&1 || analyzer_status=$?
    fi
    # Exit 1 accompanies findings. Other failures, or exit 1 without a
    # diagnostic, must not disappear when we filter the documented findings.
    if [[ "$analyzer_status" -ne 0 ]] && {
        [[ "$analyzer_status" -ne 1 ]] || ! grep -qE "^(warning|error)" "$current"
    }; then
        echo "error: circomspect exited with status $analyzer_status for $f" >>"$current"
    fi
    cat "$current" >>"$raw"

    # First line of every warning/error for this file.
    grep -E "^(warning|error)" "$current" >"$findings" || true
    total=$((total + $(grep -cE "^(warning|error)" "$findings" || true)))
    for entry in "${COUNTED_ALLOWLIST[@]}"; do
        IFS='|' read -r entry_file expected message <<<"$entry"
        [[ "$entry_file" == "$f" ]] || continue
        found=$(grep -cF "$message" "$findings" || true)
        if [[ "$found" -eq "$expected" ]]; then
            grep -vF "$message" "$findings" >"$findings.tmp" || true
            mv "$findings.tmp" "$findings"
        else
            echo "error: $f: allowlist expects $expected finding(s) matching '$message', found $found" >>"$mismatch"
        fi
    done
    cat "$findings" >>"$unexpected"
done

# Subtract the findings that are intentional in every file.
for allowed in "${ALLOWLIST[@]}"; do
    grep -vF "$allowed" "$unexpected" > "$unexpected.tmp" || true
    mv "$unexpected.tmp" "$unexpected"
done
cat "$mismatch" >>"$unexpected"

remaining=$(grep -cE "^(warning|error)" "$unexpected" || true)
allowlisted=$((total - remaining))
[[ "$allowlisted" -lt 0 ]] && allowlisted=0

echo "circomspect: ${total} finding(s), ${allowlisted} allowlisted, ${remaining} unexpected"

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
