# Expected-outcome test pack

A predeclared case list for the two evaluation tracks in the
[grok bot handoff](https://github.com/repfigit/clearproof) — policy replay /
observation (track A) and encrypted history review (track B).

Decide the expected label **before** running a case, then record the observed
label and every difference. A matching label is not proof of correctness; a
mismatch is a finding even when the result looks plausible. These cases use
synthetic fixtures and development artifacts only.

Use the [report template](report-template.md) for each attempt. Keep the exact
source revision, artifact directory, reviewer configuration digest and commands
with the records.

## Prerequisites

- Complete a `scripts/test_pilot_mirror.py` run per
  [local pilot acceptance](../operations/local-pilot-acceptance.md). It writes the
  reports referenced below under its output directory and keeps real service
  state local.
- Keep the reviewer key from `private/reviewer-key.json` and the generated
  `reviewer-trust.json` with the retained run directory, never in the reports.
- For track B, use the exported `history.encrypted.json`, `reviewer-trust.json`,
  `history-clock.json` and a separately pinned artifact/runtime/Node tuple.
- Work on a copy of the run directory. Serve the review from a process with no
  network access.

## Test-pack record

For every case record:

| Field | Value |
| --- | --- |
| Case ID | |
| Predeclared expected label | |
| Predeclared expected reason | |
| Observed label | |
| Observed reason / exit code | |
| Evidence file and digest | |
| Wall-clock and active review time | |
| Difference and interpretation | |

## Track A — policy replay and observations

Harvest the base reports from a successful acceptance run. Run each case against
the same policy and the same artifact pins. The case is the only variable.

| ID | Case | Expected | Where to look |
| --- | --- | --- | --- |
| A1 | Unmodified synthetic ALLOW fixture | `ALLOW`, agreement with the stored decision | `observations.json`, `policy-comparison.json` |
| A2 | Amount raised above the fixture's configured value limit | `DENY` (or `REVIEW` only if the active policy declares it) | policy rule in `policy-comparison.json` |
| A3 | Sanctions snapshot older than the policy's maximum age | `INDETERMINATE` | observation reason and cohort counters |
| A4 | One required credential fact removed from the input | `INDETERMINATE`, not `DENY` | observation reason |
| A5 | One public-signal digit altered | invalid pairing, `INDETERMINATE` (never a policy pass) | observation result, pairing fields |
| A6 | Original case replayed with evidence reordered and a second delivery | same label as A1 | duplicate/reorder disposition |

Notes:

- A4 distinguishes "policy said no" from "we could not establish the input".
- A5 must fail before the policy is consulted; a policy label for a tampered proof
  is itself a finding.
- Record complete, failed and indeterminate outcomes with a denominator. Do not
  discard retries; label them.

## Track B — encrypted history review

Use `clearproof verify-history` (CLI 0.7.2) with `--python`, `--bundle`,
`--trust`, `--artifacts`, `--runtime`, `--node` and the 64-hex reviewer key on
stdin. The optional `--verified-at` pins the reviewer clock. Exit codes:
`0` supported, `1` contradicted, `2` indeterminate. Output schema is
`clearproof-history-report-v1` and outcomes are `supported`, `contradicted`,
`indeterminate`.

| ID | Case | Expected | Expected reason |
| --- | --- | --- | --- |
| B1 | Untouched bundle, independently provisioned trust, correct key | `supported`, exit 0 | none |
| B2 | One ciphertext byte flipped | `contradicted`, exit 1 | `bundle_integrity_mismatch` |
| B3 | One record removed from the manifest and the payload | `indeterminate`, exit 2 | `missing_evidence` |
| B4 | One trust authority removed from the reviewer configuration | `indeterminate`, exit 2 | `decision_authority_unavailable` / `historical_status_authority_unavailable` / `statement_trust_unavailable` (record which) |
| B5 | Wrong 64-hex reviewer key on stdin | `indeterminate`, exit 2 | `history_input_unavailable` |
| B6 | Clock set before the recorded authorization, or beyond the trust window | `indeterminate` (never `supported`) | timing/status reason |
| B7 | Bundle reviewed twice, same inputs | identical report and exit code | none |

Notes:

- A `contradicted` result must name the failing layer. Do not collapse a missing
  authority into a tamper finding.
- The reviewer key and trust store are not in the bundle; removing network access
  must not change B1.
- B5 covers the CLI input guard, not decryption of every record; record which
  process rejected the input.
- A supported result covers the recorded local decision only — not settlement,
  counterparty acceptance or the truth of the simulated sources.

## After the pack

Report the count per label, the reasons observed and every deviation from the
predeclared expectation. State clearly whether the evidence answered the review
task you defined. Then open the
[evaluation feedback form](https://github.com/repfigit/clearproof/issues/new?template=evaluation.yml)
with the synthetic summary.
