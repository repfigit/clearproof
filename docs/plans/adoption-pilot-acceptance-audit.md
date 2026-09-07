# Adoption pilot acceptance audit

Audit baseline: `1f357ec`. Scope is the original M0–M5 / CP-001–CP-018 plan in
[the implementation plan](2026-09-05-adoption-pilot-implementation.md). This is an
open audit, not a completion certificate. The execution ledger supplies evidence
candidates; each requirement still needs a current source/behavior review.
A passing aggregate test count does not close an unchecked requirement.

## Requirement inventory

| Requirement | Evidence to inspect | Audit status / next check |
| --- | --- | --- |
| CP-001 bounded proof parsing and migration | `src/storage/proofs.py`, `src/storage/signals.py`, migrations; real `test_proof_storage.py` suite | 32 database cases are now included in the 76-test local command. Review exact legacy grammar, row shape, bounds and rollback assertions. |
| CP-002 reader/deployment cache isolation | `src/chain/reader.py`, chain cache tests, operations cache guide | Review keys, concurrent requests, expiry, false/zero caching and invalidation. |
| CP-003 cross-language discovery and egress | Python discovery publisher/client, TS discovery client, shared fixtures, real TLS transport tests | Review requested identity/key purpose/version routing and actual connected-address enforcement, redirects/rebinding and explicit enterprise endpoints. |
| CP-004 canonical transfer/context | `specs/transfer-evidence-v1.md`, protocol transfer/canonical models, TS commitments and fixtures | Review cross-language normalization, chain/asset distinction, amount bounds, participants and contexts. |
| CP-005 durable tenant state and issuance/proving | Pilot store, enrollment, issuance, current proof services and PostgreSQL authorization tests | Review each retained entity, restart/isolation, same-store wiring, actor-bound idempotency and concurrent consumption. |
| CP-006 authenticated credentials | ADRs 0003/0009, credential/issuance circuits, enrollment/root services, adversarial witness tests | Review unauthorized/unissued/substituted credentials and holder/jurisdiction binding with real witnesses. |
| CP-007 current verifier parity | v2 signal spec, current inspection/authorization services, SDK/CLI, current registry and real EVM fixtures | Review all named roots/freshness/expiry/future-time/domain/participant/status/revocation/replay cases. Confirm public SAR removal and legacy/current profile separation. |
| CP-008 recipient encryption and evidence integrity | Recipient/information/decision authorities, HPKE envelope, pilot cipher, authorization/export tests | Review wrong recipient/key/AAD, overlap/retirement, no fallback, tampering and separation from consumption. |
| CP-009 manifests and doctor | Artifact model/loader and doctor entry point, source inventory, runtime pins and negative artifact tests | Review mixed/missing/unapproved profiles, production rejection and minimized diagnostics; compare actual generated digests. |
| CP-010 policy evaluation | Python policy model/evaluator, signed facts/valuations, policy evaluation API tests | Review four outcomes, bounds, conflicting/stale/missing sources and distinction between predicates/obligations. |
| CP-011 policy comparison and review | Diff/approval/activation services, API and built CLI tests, retained comparison | Review before/after rule explanations, missing/unsupported coverage, review delta, expected outcomes and read-only replay. |
| CP-012 append-only events | Event model, ingestion/index transactions and process-death tests | Review source/business identities, separate clocks, atomicity, duplicates/order and tenant collisions. |
| CP-013 provider and bilateral semantics | Fireblocks adapter/intake, signed fixture, bridge/counterparty, local exchange and CLI tests | Review detached-byte authentication, required message semantics and explicit local-simulator boundaries. Official provider/protocol reviews are recorded in their implementation docs. |
| CP-014 readable investigation/queue and provider links | Reconciler, scoped timeline/queue API and CLI | **Provider-link gap closed:** scoped operator catalogue, API/queue fields and readable CLI now have tenant/transfer/source filtering, malformed-configuration and client-validation coverage (30 focused Python, 13 CLI, 76 PostgreSQL/EVM tests passed). Review every named lifecycle scenario before closing the whole item. |
| CP-015 historical evidence | Exporter, history statement/status/timing verification, reviewer schema and offline CLI tests | Review independently configured trust, all four times, modified/missing/swapped inputs, compromise/expiry, tenant access and replay prevention. Fresh retained export was reproduced with sockets disabled. |
| CP-016 observation onboarding/scenarios/metrics | Durable observations/cohort, CLI, bilateral scenarios, combined custody investigation | Review all six counterparty scenarios, duplicate/reordered custody, coverage/disagreement/latency denominators and no enforcement side effects. |
| CP-017 setup, compatibility and operations | Lockfiles, owned local runner, CI, local acceptance and migration guides | Fresh setup/build/artifact/service/offline evidence exists. **Documentation review remains:** a consolidated compatibility matrix and actionable observability coverage have not been located. Check runbooks, stale claims and links against the final implementation. |
| CP-018 paid-pilot preparation and counters | `docs/commercial/`, usage service/API and tests | Review brief, interview, baseline worksheet, pricing hypothesis, free/paid boundaries and counter retry/deduplication semantics. No customer or revenue claim may substitute for preparation. |

## Cross-cutting closure checks

- Inspect the original acceptance text for every row, including prose outside its table.
- Match negative tests to the actual trust boundary; mocked business tests do not establish circuit validity.
- Verify final `make test`, uncached workspace/contract tests with explicit fresh artifacts, build/noEmit and changed-file Ruff checks. Distinguish skipped optional/service cases from the separate live-local gates.
- Verify the fresh-checkout synthetic workflow and its retained observation/comparison/investigation/export outputs. Review scoped identifiers instead of assuming separate fixtures are one customer transfer.
- Reproduce the encrypted export offline with separately configured synthetic trust and the declared review clock; confirm exact output and no secret/plaintext leakage.
- Check signal/spec/vector/artifact alignment, release references, compatibility, migration/rollback instructions, observability and the final diff.
- Record an authoritative source/test result for each closure. Missing or indirect evidence remains open.

F1–F5 are separate follow-on gates. This audit cannot establish live provider
interoperability, customer adoption, willingness to pay, managed distribution,
independent assurance or production readiness from local simulations.
