# Evaluating Clearproof examples and evidence

Use this guide to record whether a supported example is reproducible and whether
its evidence is useful for a specific review task. It is not a compliance
certification or a production readiness assessment.

## Reproduction record

Record the source revision, package and artifact versions, operating environment,
prerequisites, exact commands, expected outcome, observed outcome and any manual
intervention. Separate time spent installing prerequisites from active task time.
Keep failed and incomplete attempts visible rather than counting only successes.
Use synthetic data in public reports; follow [security reporting](../../SECURITY.md)
for sensitive findings.

## Evidence review

Define the cohort and expected labels before evaluation. Include missing or stale
inputs, duplicate/reordered events and tampered exports alongside successful cases.
Record complete, incomplete and error outcomes with their denominators. Measure
active investigation time separately from wall-clock resolution time. State which
source assertions are trusted and what the supported proof/export actually verifies.
An independently reviewed record is not evidence that a transfer settled.

## Adoption signals

Distinguish an example start from successful completion and a second use from a
first visit. GitHub stars, clones and outbound link clicks are discovery signals;
none establishes successful installation, an active organization or willingness
to pay. Feed requests do not establish unique subscriber counts. Missing metrics
are unknown, not zero; do not fingerprint anonymous visitors across services.

For comparisons, use the same eligible cases and task in both workflows, describe
the method, and retain errors and manual work. Report observed counts, median and
upper-tail durations where meaningful, sample size and limitations. Do not infer
broad benefits from a small selected sample.

The [observability guide](pilot-observability.md) covers operational diagnosis.
The [usage inventory](usage-inventory.md) describes metadata counters; it is not
an activity, adoption or billing ledger.
