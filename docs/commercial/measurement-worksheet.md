# Pilot baseline and outcome worksheet

Complete before the pilot cohort is evaluated. Leave unknown values blank and
label them unknown; do not substitute zero. Store case details in the authorized
encrypted system, using opaque references in this worksheet.

## Predeclared study

| Field | Value to complete |
| --- | --- |
| Tenant/prospect alias; measurement owner; budget owner | |
| One job/workflow and existing alternative | |
| Observation window and source inventory | |
| Cohort inclusion/exclusion rules and selection owner | |
| Total eligible cases; selected cases; distinct transfers | |
| Policy, source and artifact versions; baseline label owner | |
| Baseline label provenance and unresolved labels | |
| Synthetic vs customer-authorized data; access/retention approval | |
| Success target, maximum acceptable gaps and stop criteria | |
| Measurement method; clock/units; missing data handling | |

Compare the same job and case mix. Keep raw numerator and denominator alongside
any percentage. Multiple observations of one transfer are not multiple customers
or transfers. Report excluded/unavailable cases and any post-hoc cohort change.

## Measures

| Measure | Baseline and pilot method | Required evidence / caveat |
| --- | --- | --- |
| Onboarding effort | Engineer active minutes and elapsed time from agreed prerequisites to first usable report | Start/stop events, blockers and manual assistance; local setup gate still open |
| Supported-case coverage | Determinate policy cases / selected cases, with observed and missing counts separately | Cohort report; no inferred coverage of the unselected population |
| Decision disagreement | Disagreements / comparable labelled policy cases | Cohort report plus label provenance; unverified labels are not ground truth |
| Unexplained disagreement | Disagreements remaining unresolved after a named reviewer investigates / all disagreements | Review log; not inferred automatically from comparison count |
| Exception diagnosis | Active minutes and elapsed time from exception detection to a documented cause/next action | Timestamped observer notes; compare same task and case mix |
| Stale-input exposure | Cases rejected or delayed for stale inputs / eligible cases, with age and source identified | Controlled scenario or authorized source logs; distinguish missing from fresh |
| Evidence completeness | Cases with the agreed required evidence / selected cases; separately count supported/contradicted/indeterminate offline results | Reviewer configuration, export references and actual offline results |
| Evaluation duration | Measured count, total/min/max nanoseconds; derive mean only with nonzero measured count | v2 observation cohort; excludes network, preflight, lock wait, persistence and external settlement |
| Repeated use | Distinct authorized operator days and repeated task completions over the window | Approved activity log; record counts alone do not prove operator adoption |
| Delivery cost | Engineer/support hours, compute, storage/backup and vendor cost by engagement | Actual cost sheet; ciphertext bytes are not total disk or hosting cost |

## Result row (repeat per measure)

Metric / unit / cohort reference / baseline numerator-denominator / pilot
numerator-denominator / missing count / change / evidence reference / reviewer /
confidence and limitations / decision.

Do not claim statistical generalization from a small convenience cohort. Preserve
raw durations; use median/P95 only with the sample size and calculation method
shown. Current automated counters are an inventory, not a time-series activity
ledger, and do not measure adoption or billable usage by themselves.
