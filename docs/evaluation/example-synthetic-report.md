# Example evaluation: internal synthetic rehearsal

This is a curated summary of an actual internal local acceptance run. It is not
an external operator evaluation, a live counterparty trial or production approval.
The record is intentionally incomplete where the retained run did not measure or
capture a field. No private run files are published with this summary.

| Field | Retained observation |
| --- | --- |
| Task | Reproduce the local acceptance workflow and inspect a recorded policy decision |
| Evaluator | Internal agent; no independent operator or counterparty |
| Outcome | `acceptance-tests-passed` for the local acceptance suite |
| Proof/profile assurance | `development-unapproved` |
| Source authenticity | `local-simulators-and-synthetic-fixtures` |
| Clean environment | `not-established` |
| Source revision | Not recorded in the retained run inventory; unknown |
| Package/tool versions | Not recorded in the retained run inventory; unknown |
| Installation, active review and wall-clock time | Not measured in this record; unknown |
| Attempts/failures across earlier setup work | Not retained as an attempt ledger; unknown |
| Report inventory | Nine scoped reports, with byte counts and SHA256s |
| Adopted customers, repeat users, willingness to pay | Not assessed |

## Observed evidence review

The retained `clearproof-history-report-v1` reports `outcome: supported` for
`scope: recorded-local-policy-decision`. Cryptographic validity, statement
validity, export integrity, decision/information/status authentication and policy
reproduction are true. Its timing check is authenticated against the supplied
local test trust, not an independent production timestamping assurance claim.
These results establish the fixture's supported offline review, not settlement
or the truth of simulated source assertions.

The history report's SHA256 is `47d2075d9f60b7f1129950b279ca80785ca6b423453aba8f196215b06c1a519e`.
The development artifact manifest pin is `3b43dc570ad6dc2f64f442e7914833963952d97c26d6f3e2bf27786c01ce3098`.
Neither digest establishes an audited setup or production artifact approval.

## Interpretation and next evaluation

This run supplies internal reproducibility/evidence checks. It cannot support a
claim that an external reviewer completed the task, that integration was easy,
or that Clearproof saved review time. The next evaluator should record the exact
revision/environment and every attempt before running the workflow, use the
same predefined cases for any comparison, and measure active review time.
A permitted operator/counterparty evaluation remains outstanding.

Reproduce using the [onboarding guide](../operations/onboarding.md) and fill the
[report template](report-template.md). Preserve private keys, stores, logs and
real records outside public reports.
