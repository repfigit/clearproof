# October project improvements

Status: active. Scope includes the core repository, clearproof-web, hosted
documentation, all seven open Clearproof Linear issues and all five open GitHub
issues reviewed on October 5. Completion requires verified behavior and tracker
reconciliation, not merely a change of issue status.

The preexisting issue inventory is GitHub #85, #86, #87, #88 and #89, plus
Linear AIF-158, AIF-119, AIF-100, AIF-99, AIF-89, AIF-67 and AIF-65.
These twelve items remain part of the task list alongside the website and
documentation recommendations. GitHub #89 and Linear AIF-89 are separate work.

| Work | Completion evidence | State |
| --- | --- | --- |
| Website dependencies and maintenance | Patched framework, dependency audit disposition, lint/build/browser/link CI, deployed verification | Done; web #12 merged, production Ready and live checks passed |
| Shared release and publication catalogue | Homepage and docs consume one status/catalogue; future/paused articles not promoted; live links work | Shared catalogue deployed; fresh registry verification requires the 0.6.0 npm / 0.7.0 source correction in #101 to merge and deploy |
| Documentation accuracy and presentation | Reconciled roadmap/agent guidance, proper Markdown, technical sitemap/metadata, maintained web README | Done; #91/web #12 merged and deployed with browser acceptance |
| Two onboarding paths | Small synthetic evidence inspection with tamper case; reproducible complete pilot with preflight/recovery; current SDK example first | Done; #98 merged after 23 exact-head checks and exact approval, with production docs Ready and live guidance verified |
| Backlog reconciliation | Source/test evidence for every open Linear/GitHub item; delivered work closed and remaining criteria retained | In progress; nine of the original twelve issues closed with evidence |
| Artifact isolation (GitHub #85) | Explicit test bundles required; incomplete supplied bundles fail; local ambient artifacts ignored | Done; #91 merged and fresh-bundle CI passed; GitHub issue closed |
| Dependency cleanup (GitHub #86) | Unused drivers removed; locked install and relevant Python tests pass; storage guidance accurate | Done; #91 merged, locked install and full remote CI passed; GitHub issue closed |
| Proving execution (GitHub #87) | Correct service scope; durable bounded jobs, privacy-safe input/output, retries/cancellation/concurrency/freshness tests | Done; #94 merged after full exact-head CI and approval, GitHub issue closed |
| Native proving benchmark (GitHub #88) | Equivalent current-profile benchmark; measured backend decision; pinned optional backend if justified | Done; #95 merged after final-head CI and active approval; GitHub issue closed and native deployment guidance verified live |
| Canonical constants (GitHub #89) | Structured profile source, generated runtime constants, drift gate and cross-runtime compatibility tests | Done; #93 merged after full current-head CI and approval; GitHub issue closed |
| Operational preflight and software scale | Scoped authenticated readiness checks, bounded cryptographic execution, paginated persisted inventories and measured limits | Readiness #99 merged and deployed; pairing #100 and inventory #101 locally validated with measured limits, awaiting latest-revision CI/review, merge and deployment |
| Legacy configuration/parity and migration issues | AIF-158/89 hardened with compatibility; AIF-119/100 reconciled; AIF-67/99/65 remaining acceptance explicitly verified | In progress; AIF-158/119/89/100 merged or reconciled and closed; AIF-67/99/65 remain open |
| External evaluation and adoption | Evaluation/feedback entry point and sample report; permitted real operator/counterparty evaluation with retained measurements | Entry, feedback form and internal sample locally validated; website #18 opened. Core review/merge/deployment and a permitted real partner evaluation remain outstanding |
| Production assurance | Existing F1–F5 start conditions preserved; independently reviewed artifacts, audits and live interoperability cannot be inferred from local tests | External gates remain open |

## Verified tracker reconciliation

- Original issue inventory: GitHub #85, #86, #87, #88 and #89, and Linear AIF-119,
  AIF-158, AIF-89 and AIF-100 are closed. Linear AIF-99/67/65 remain open;
  their original acceptance criteria still apply.

- **AIF-119: Done.** Seven-argument router fixtures are already on public main
  at `33be493`. Local complete normal-bytecode Hardhat run: 121 passed, 32
  artifact-gated pending, no constructor errors. Main
  [hardhat-tests](https://github.com/repfigit/clearproof/actions/runs/37377205666/job/111989330905)
  and [real-artifact circuits](https://github.com/repfigit/clearproof/actions/runs/37377205666/job/111989330993)
  are successful. Linear received this evidence, moved to Done and had its
  agent-ready label removed. Other open issues retain their acceptance criteria.

## Execution log

- October 5: rechecked clean worktrees and remote branches; website checkout was
  behind its published explainer-link change and was updated on an isolated branch.
  Registry confirms stable Next.js 16.3.8 and React 19.3.0. Implementation started
  with website dependency remediation and a shared public project catalogue.

Customer/provider access, independent assurance and production approvals require
actual external evidence; local tests cannot establish those prerequisites.

- October 5: website [PR #12](https://github.com/repfigit/clearproof-web/pull/12)
  contains dependency remediation, a request-time shared catalogue client,
  publication filtering, explicit synthetic-demo labels, robots/sitemap, CI and
  maintenance documentation. Local lint/typecheck/build, 18 unit checks and eight
  desktop/mobile/Firefox/WebKit browser checks pass. Production npm audit: zero
  advisories; five development-only braces/ESLint entries remain unpatched.
  Both site deployments and the live link check are still pending.
- October 5: core documentation uses the shared status source, renders proper
  CommonMark/GFM without HTML, inventories every technical page in its sitemap,
  and checks static page-specific metadata for drift. Documentation: 115 unit
  tests at 100% measured app coverage; content: 25 tests at 100%. PostCSS is pinned
  to patched 8.5.29, with a successful production docs build. Core production
  audit still reports five high build-chain and 15 low comparison-tool entries;
  no claim of a fully clean dependency tree is made. Documentation browser acceptance: 80 checks passed in the full run; the four
  root-page canonical assertions were corrected and passed on a focused rerun.
  Hosted deployment and full remote CI verification remain required before
  closing this work.

- October 5: core maintenance [PR #91](https://github.com/repfigit/clearproof/pull/91)
  links GitHub #85/#86 and the shared documentation catalogue consumed by web
  PR #12. Main's stale AIF-119 constructor issue is closed with execution/CI
  evidence. Removed agent-ready from all eleven other completed Clearproof
  issues, preserving their other labels and completion state.
- October 5: AIF-158 implementation requires stable HKDF salt at API startup and
  direct legacy derivation, with an explicit local-demo-only opt-in. Configured
  UTF-8 salts preserve existing derivation; retained legacy ciphertext migration
  is documented and tested. Focused encryption/startup checks: 51 passed, 100%
  changed-module coverage. Full Python suite: 2,442 passed, 274 optional/service
  skips, zero HKDF salt warnings under a warning-as-error gate. Remote real-service
  CI and merging remain required before the issue is closed.

- October 5: #91 merged as `8a7c428` after every required check and automated
  approval succeeded. Fresh development setup, actual legacy/pilot proofs,
  PostgreSQL acceptance, normal-bytecode E2E and aggregate coverage gates passed
  in run [37381888518](https://github.com/repfigit/clearproof/actions/runs/37381888518).
  GitHub #85 and #86 are closed. Production docs deployment
  `dpl_F2bYk9Nt2apWV7gmZjB5eznYjG21` is Ready; its public catalogue reports
  0.7.0 / pilot-transfer-v3 and eight currently published explainers, excluding
  the October 7/12 articles.
- October 5: AIF-158 is In Review under [PR #92](https://github.com/repfigit/clearproof/pull/92).
  Clearproof's Linear project is now In Progress. A concurrent PR #90 duplicates
  the now-merged #86 dependency cleanup; its additional supervisor-driver
  correction is preserved here before reconciling that duplicate.

- October 5: website #12 merged as `f277842` after exact-head CI and approval.
  Production deployment `dpl_2VxB6B8kU6qVVvVXeMfLpDTUAo2v` is Ready at
  clearproof.world and www.clearproof.world. Live verification passed all 13
  linked documentation pages, robots/sitemap and release status. Final source
  checks: 22 unit tests and eight browser checks. Core #92 merged as `b689aea`
  after full CI run [37383711024](https://github.com/repfigit/clearproof/actions/runs/37383711024),
  including PostgreSQL, actual proofs and aggregate coverage. AIF-158 is Done
  with retained-ciphertext compatibility evidence. Duplicate #90 was closed as
  superseded; its extra supervisor-driver correction is preserved in #92.

- October 5: GitHub #89 implementation generates constants and public declarations
  from `specs/pilot-signals-v3.json` for Python, TypeScript, Solidity, Circom,
  source-package metadata and specification tables. A read-only CI drift check
  rejects stale outputs; malformed and ambiguous schema input is rejected before
  writing. Previous source, generated repository source and packaged source all
  compile to the identical R1CS SHA256
  `4248cc7b67e7ead5a4ac7a4425acd0debffaee9642d540846be58daeae551aa8`.
  Checks: full Python 2,529 passed / 274 optional skips; generator/cross-layer
  focused suite 95 passed with 100% generator branch coverage; SDK 222 passed
  at 100% coverage; normal-bytecode contracts 121 passed / 32 artifact-gated
  pending; source package six passed, including packed include resolution.
  Remote actual-proof/coverage CI, review and merge remain required before
  GitHub #89 closes. No compiled keys or artifacts are committed.

- October 5: [PR #93](https://github.com/repfigit/clearproof/pull/93) contains the
  canonical profile implementation. Initial CI exposed generator formatting and
  an escaped SPDX header being interpreted as an invalid license expression.
  The renderer now emits repository-formatted Python and a literal valid SPDX
  header. Full Ruff lint/format, REUSE and 95 focused tests at 100% generator
  coverage pass locally; updated full remote CI remains required.

- October 5: #93 merged as `61271b7` after all current-head checks, including
  real circuit/proof and PostgreSQL acceptance, succeeded and an approving
  review was recorded. GitHub #89 is verified closed. GitHub #87 remains open:
  local encrypted PostgreSQL queue and memory-only prover foundations are
  implemented and tested, but the complete worker/API and freshness workflow
  remains to be delivered.

- October 5: #87 now includes the separate supervised Linux worker, authenticated
  admission/read/cancel/retry routes, an operator-owned shared target factory,
  current-state checks at witness preparation, fenced completion and result
  retrieval, plus repository/public operations documentation. Queue tests:
  35 passed at 100% branch coverage; backend tests: 38 passed at 100%; API,
  factory and worker lifecycle checks: 62 passed at 100% across those modules.
  Actual development-artifact acceptance: five passed, including revocation,
  approved-root advancement and target replacement during real proving; stale
  results are withheld after completion. Documentation: 115 tests and a
  production build pass. Ruff/format, diff checks and REUSE pass. Full local
  PostgreSQL/artifact Python regression, remote CI, review and merge remain
  required; GitHub #87 is still open and no development keys are committed.

- October 5: review identified that a proving worker can legitimately run as PID
  1 in a container. The launcher now receives its expected parent PID explicitly,
  accepting that case while rejecting reparenting races and failed parent-death
  setup. Backend checks now total 42 passing tests at 100% branch coverage;
  a fresh real-proof check covers the updated launcher.

- October 5: full PostgreSQL/artifact regression completed with 2,943 passing
  tests, two optional skips and two failures in historical migration fixtures.
  Those fixtures removed later version rows while leaving newly introduced queue
  tables, or assumed version 20 was still latest. They now reconstruct their
  actual historical schemas before upgrading. Both corrected fixtures and a
  new prequeue-upgrade test passed against PostgreSQL, preserving retained
  encrypted evidence and proving the upgraded queue usable. Exact-revision full
  regression is being repeated with the optional CLI acceptance enabled.

- October 5: the exact-revision repeat at `9647bde` passed: 2,950 tests,
  two optional skips and 100% measured Python branch coverage. All ordinary
  remote CI checks passed for that revision. Review then identified that a
  target deadline ahead of PostgreSQL's clock could reject admission. The queue
  now caps the admitted expiry against the database clock and retains the
  original absolute limit encrypted for stable idempotency. Clock-skew,
  shortened-deadline and repeat-admission regression checks pass against real
  PostgreSQL. The focused queue/API/worker and actual-proof suite passed all
  83 tests with 100% coverage of the queue and service. Updated full regression,
  remote CI and approval remain required before #87 can close.

- October 5: the clock-skew revision `abce008` passed the full local
  PostgreSQL/artifact/CLI regression: 2,956 passed, two optional skips and
  100% src statement/branch coverage. All exact-head remote checks, including
  fresh circuits, PostgreSQL and aggregate coverage, succeeded. Bugbot cleared
  the finding and an approving review was recorded. #94 merged as `300bb2c`;
  GitHub #87 is verified closed. Documentation deployment
  `dpl_VcxEaWoYL539irdgCVR76dZQar8q` is Ready at `docs.clearproof.world`;
  live API/deployment pages include the new routes, roles and worker factory.

- October 5: #88's equivalent current-profile prove-only comparison used the
  same development key/WTNS and four physical cores. Five measured invocations
  per implementation: snarkjs median 4.91 seconds / 2,595.3 MiB peak process RSS,
  native median 1.05 seconds / about 86 MiB. All 18 warmup/measured proofs paired
  independently and matched the expected eight signals; altered statements were
  rejected. The measured ratio is 4.7, not a claimed universal 10–30-fold gain.
  The optional native backend uses sealed anonymous memory, operator binary
  pins, guarded subprocesses and independent JS pairing. Its 66 transport,
  pinning, cancellation, replacement and worker-crash checks initially passed
  at 100% branch coverage; two additional executable/permission-failure checks
  bring the module total to 68. The focused factory/API/worker and real-proof
  regression passed all 132 tests with 100% native/service branch coverage.
  Documentation: 115 unit tests and a production build pass; SDK/CLI builds,
  Ruff/format and REUSE pass. The final source-pinned build
  recipe completed and yielded the same observed binary SHA256 as the benchmark.
  Full regression, remote CI, review and merge remain before #88 can close.

- October 5: the native revision `4fea6f1` passed the full local PostgreSQL,
  both-profile, native and CLI regression: 3,027 passed, two optional skips,
  100% src statement/branch coverage (9,523 statements; 2,376 branches).
  Ordinary Python CI identified a test-worker import dependency on the parent's
  `PYTHONPATH`. The crash test now supplies its repository import path explicitly
  and removes inherited `PYTHONPATH` when launching the worker. Production code
  is unchanged. The ordinary suite passed after clearing optional artifact,
  service and import-path settings: 2,668 passed, 361 optional skips. Updated
  exact-head CI and approval remain required before #88 closes.

- October 5: AIF-89's current input reproduces the historical fixture's complete
  16-signal statement through a real witness/proof round trip. The development
  build now retains matching input/proof/public/vkey files and their actual
  hashes together, with explicit unapproved-key warnings. The recorded vector
  remains intentionally threshold-policy negative and has no chain binding.
  Ordinary SDK checks fail if a committed file is missing or a declared public
  input drifts. Actual development-artifact regression covers public-statement
  divergence and an inconsistent private credential preimage; neither publishes
  a vector. The documented fresh build passed five Python real-proof checks and
  32 normal-bytecode Hardhat checks, including the legacy E2E flow. The complete
  SDK suite passed 223 checks at 100% coverage, and the development runner reached
  100% statement/branch coverage. The artifact-producing CI job is explicitly
  named UNAPPROVED development circuits; the existing circuits check gates its
  success. Full remote CI, review, merge and tracker reconciliation remain.

- October 5: #95 merged as `3d18674` after all 22 final-head checks passed,
  including source-built native proofs, PostgreSQL, real EVM acceptance and
  aggregate coverage. The active approving review covers unchanged production
  source; the final follow-up changed only test-worker imports and this log.
  GitHub #88 is verified closed. Documentation deployment
  `dpl_GEbD23SjBi6TdSqy4opW82rTKgXG` is Ready from that exact merge revision;
  live deployment guidance includes the native binary/hash settings and factory.
  AIF-89 is In Review under PR #96, rebased onto this merged native work; its
  updated complete CI and review remain required.
- October 5: the user expects an existing funded testnet account on file and
  confirms that no real evaluation partner exists yet. The deployment manifest
  supplies a historical public deployer address; local configuration and GitHub
  repository secret metadata contain no signer. Deployment-environment lookup
  is unresolved. Live benchmarks still require verified account access and
  funding; real operator evaluation remains open.

- October 5: AIF-100 is In Review under PR #97. Permanent selector/address/runtime-hash
  bindings reject pending or historical overwrite. Registration, delayed default
  selection and retirement are separate operations; delay changes are delayed and
  retain an immutable deployment floor. Former registry defaults have a bounded
  24-hour explicit-selector path, retaining domain/current-state checks and shared
  nullifiers. Emergency disable terminates grace immediately. The restartable
  replacement script resumes both timelocks without duplicate deployment. Real
  development proofs pass through a swap, retirement grace and a new default;
  wrong domains and tampered statements are rejected. Full contract validation:
  166 passed with normal bytecode, and 166 passed at 100% measured Solidity
  statement/branch/function/line coverage. TypeScript checks pass. Documentation:
  115 tests at 100% measured app coverage and a production build pass. Repository
  and public contract guidance describe historical Sepolia's missing router and
  required one-time migration; no remote migration or historical shutdown is
  claimed. Full remote CI, review and merge remain before tracker closure.
- October 5: current Clearproof and contracts checkouts contain only `.env.example`
  templates. The web, Vercel docs and separate Clearproof Hermes environment files
  have no deployer-key or RPC settings. GitHub exposes Preview and Production
  environments; the workflow's sanctions-relay environment is not present.
  Read-only checks of the historical deployer return zero balances on Base,
  Arbitrum and Optimism Sepolia. Ethereum Sepolia RPC reads did not succeed,
  so its funding remains unverified. Existing account access is still unresolved;
  no transactions were sent and no evaluation partner exists yet.

- October 5: #96 merged as `e12aa27` after all 23 checks passed on its final
  revision `cae630d`, including fresh development artifacts, PostgreSQL,
  native proofs, complete EVM acceptance and aggregate coverage. The approving
  review is on that exact revision. AIF-89 is verified Done in Linear with its acceptance evidence retained
  and agent-ready removed. AIF-100 is In Review under PR #97 and is rebased onto the parity
  merge; its refreshed CI and review remain required.

- October 5: the parity merge's production docs deployment
  `dpl_8tHQFNvijD9WTShPMRfMYkoGG9qd` is Ready from exact revision `e12aa27`,
  with the docs.clearproof.world alias and live deployment-page checks verified.
  AIF-100's rebased PR #97 received an approval on `de6066b`. Its operational
  JavaScript gate exposed old deployment-script mocks that lacked the new ABI
  and assumed immediate selection. Updated both-delay, retry, incompatible-ABI
  and failure-path checks: all 181 passed, with 100% coverage of 699 statements,
  274 branches and 51 functions across 12 operational modules. This follow-up
  changes tests and this log only; refreshed full CI remains required.

- October 5: #97 merged as `9f536a9` after all 23 exact-head checks passed on
  `c388ae7`, including fresh proofs, real services and aggregate coverage. The
  active approval on `de6066b` covers unchanged production code. AIF-100 is
  verified Done, with its original acceptance criteria and delivered evidence
  retained and agent-ready removed. Nine of the original twelve issues are now
  closed; AIF-99/67/65 and the other recommendations retain their remaining scope.
  Production docs deployment `dpl_2goxFTZ4JSvmU7U8kHq3wy2qV37E` is Ready
  from exact revision `9f536a9`, aliased to docs.clearproof.world. Live contract
  guidance includes explicit-selector submission, grace and the historical
  deployment's initial-migration warning.
- October 5: the Node-only source example independently pairs the historical
  legacy development fixture, preserves its expected threshold rejection and
  rejects a changed public registry domain. The source quickstart and SDK guide
  now present both onboarding paths and current pilot inspection first, correct
  `proofValid` versus threshold-bound `valid`, and expose generated OpenAPI
  exploration/export. CLI/content and hosted-source documentation are reconciled.
  Local orchestration preflight checks the selected interpreter/dependencies,
  Node/Hardhat, built CLI, PostgreSQL 18 and development acceptance plus production
  rejection by the artifact doctor before creating output or services.
  Complete acceptance initially exposed two hard-coded `.venv` paths in offline
  review tests; they now use the running interpreter. The fresh repeat passed all
  223 checks, retained nine reports and a report-only inventory, and stopped both
  owned services. The failed run also stopped its services and has no success
  inventory. No clean-host provisioning or production assurance is claimed.
  Orchestration: 60 passed at 100% coverage; operational JavaScript: 44 passed at
  100%; CLI: 184 passed at 100%; content: 25 passed at 100%; docs: 115 passed at
  100% and a production build passed. The legacy demo's export preserves existing
  directories and does not invent compiler/setup provenance; an actual fresh
  development proof/export passed. REUSE, formatting and diff checks pass.
  Remote CI, approval, merge and hosted verification remain required.
- October 5: GitHub Preview and Production environments also contain no stored
  secret names. This metadata check does not locate the expected funded account;
  signer access remains unresolved. No testnet transaction was sent, and there
  is no real evaluation partner yet.

- October 5: onboarding PR #98 review caught a mislabeled tamper coordinate:
  legacy signal 14 is the nullifier; the registry domain is signal 12. Corrected
  both the example and its test, then repeated actual pairing/tamper acceptance.
  Direct preflight now resolves this checkout's scripts namespace explicitly;
  the documented invocation passes with `PYTHONPATH` removed. Orchestration
  remains 60 passing checks at 100%, and JavaScript remains 44 passing at 100%.
  The remote development gate stopped at the native source download because
  all three upstream GMP hosts timed out. An additional GNU-listed mirror
  supplies the same SHA-pinned archive. A fresh full source build passed and
  produced the same observed native binary SHA256 as the previously verified
  build; no source pin, arithmetic, setup key or compiled artifact changed.
  Updated full CI and approving review remain required.

- October 5: tenant-scoped inspection/proving readiness requires `usage:read`,
  selects only an operator-configured target and rejects query scope overrides.
  The report checks a bounded read-only PostgreSQL ping/migration history, a
  synthetic in-memory active-key round trip, loaded profile/trust/freshness and
  executable/artifact availability. It performs no proving, pairing, migrations,
  retained-customer decryption, current-head/credential reads, worker heartbeat,
  provider requests or authorization consumption. Both success/failure reports
  are minimized and not cacheable; public process liveness remains independent.
  Three real PostgreSQL checks preserve migration timestamps, record counts and
  consumption counts, reject drift without repair and retain liveness during a
  closed pool. API regression: 109 passed; new route at 100% statement/branch
  coverage. Content: 25 passed at 100%; docs: 115 passed at 100% and a production
  build passed. Ruff/format, REUSE and diff checks pass. This is configuration
  preflight, not full live/production readiness; updated CI/review and hosted
  verification remain required. Remaining inventory/scale work is still open.

- October 5: readiness review found that a valuation valid at the current clock
  can still have been signed after the configured evaluation clock. Preflight now
  verifies both clocks, matching live inspection. Two regression cases use actual
  scoped Ed25519 signatures and demonstrate rejection for inspection and proving
  without invoking either backend. All 43 readiness unit checks pass, with 100%
  statement/branch coverage of the route. Updated review and full CI remain required.

- October 5: onboarding #98 merged as `54492bf` after all 23 checks on `4e01fff`
  passed and an approving review covered that exact revision. This includes fresh
  both-profile proofs, the source-built native backend, PostgreSQL acceptance,
  full Python aggregate coverage and normal/coverage contract verification. Its
  exact-revision production documentation deployment is building. Readiness #99
  is rebased onto this merge and will run the complete main-targeted CI workflow.

- October 6: readiness #99 merged as `9dc5ec5` after all 23 latest exact-head
  checks passed and active approval covered unchanged production source.
  Production docs `dpl_FFGYwdP3kLgaavYs2WaUMgeKJmTw` are Ready from that
  exact merge; live API and deployment guidance passed. Pairing #100 is rebased
  onto this main and running fresh exact-head checks; its older approval is not
  treated as approval of new production source.
- October 6: encrypted enrollment inventory is maintained atomically on issuance,
  discovered in private 64-entry pages, and migrated by explicit validated admin
  backfill. Encrypted count heads detect incomplete indexes. Larger issuance
  sources use authenticated 128-entry pages; existing sources up to 256 leaves
  preserve their format/digest. A real accepted-profile proof from 258 enrolled
  leaves and a 32-sibling witness independently verified; deleting a source page
  prevents preparation. Initial broader PostgreSQL regression: 338 passed.
  A synthetic scan benchmark found 1,024 entries took about 17 seconds to build
  a root on the measured host. The construction guard is consequently 1,024
  scanned records across all configured issuers per refresh, retaining the
  30-second transaction timeout. Final measurements/checks, review, merge and
  hosted verification remain required; this is not a production capacity claim.

- October 6: final inventory acceptance: 104 passed, with 100% statement/branch
  coverage across inventory, issuance source and tree construction. The shared
  registrar budget counts expired/revoked entries and rolls back partial roots;
  real PostgreSQL API/backfill, audience limit, missing-head and exact retry
  cases passed. Final three-sample root medians: 1.041 / 4.319 / 8.401 / 16.730 s
  at 64 / 256 / 512 / 1,024 entries; first 64-entry pages remain 0.72–0.77 s.
  Receipts, source hashes, reproducible commands and exclusions are committed
  under `docs/benchmarks/2026-10-06-pilot-enrollment-inventory.*`. Documentation
  checks (115) and content checks (25), plus production docs build, passed.
  Updated full regression, remote CI, approval, merge and hosted guidance
  verification remain required.

- October 6: updated full inventory/storage/queue/wallet/publication regression:
  355 passed. Another 32 route, real proving-job and paged-source persistence
  checks passed, including corrupted-page rollback and safe page reuse. The
  two focused suites together exercise every statement and branch in all eight
  changed runtime modules. Benchmark source hashes match the implementation.
  Ruff/format, diff checks and REUSE pass. Remote full CI/review, merge and
  production-hosted guidance verification remain outstanding.

- October 6: the shared public capacity catalogue and ADR 0011 still described
  the old 256-record software guard. They now match the implemented 1,024-record
  shared refresh budget, paged encrypted inventory and measured synthetic
  latency, while explicitly retaining the production-scale incremental-tree
  requirement and lack of demonstrated production throughput. Updated source
  checks, full CI and review remain required before publication.

- October 6: authoritative npm metadata contradicts the earlier 0.7.0 publication
  claim: all five packages currently publish 0.6.0, and 0.7.0 is unavailable.
  Retrieved 0.6.0 tarballs confirm pilot-transfer-v3 sources/SDK support, while
  registry metadata includes signatures and attestation URLs. The public
  catalogue now separates npm 0.6.0 from workspace/source 0.7.0, and current
  install commands and README/SDK/CLI guidance use the available release.
  Earlier publication assertions in this execution log are superseded by this
  registry check. Updated documentation acceptance, CI, review and deployment
  verification remain required.

- October 6: corrected-release documentation acceptance: content 25, docs 115,
  production docs build and all 84 desktop/mobile/Firefox/WebKit browser checks
  passed. The five packed 0.6.0 tarballs match registry SHA512 integrity; SDK
  exports and current profile were inspected. The release snapshot is retained
  in `docs/releases/2026-10-06-npm.*` and public facts are checked against it.

- October 6: the evaluation workflow now includes a documentation entry, a
  voluntary synthetic-feedback form, a report template and a curated internal
  acceptance example. Missing revision, environment, attempt and timing evidence
  remains explicitly unknown in that example. The guide distinguishes pairing,
  source authenticity, policy, consumption and counterparty acceptance. No real
  evaluation partner is established; a permitted external evaluation remains
  outstanding. Final combined-source validation, CI/review, merge and hosted
  verification remain required before announcing these entry points.

- October 6: the evaluation branch includes the corrected release/capacity
  catalogue and passed 25 content checks, 115 documentation checks, production
  build and all 88 desktop/mobile/Firefox/WebKit browser checks. REUSE and diff
  checks pass. Website #18 passed lint, 22 unit checks, build/typecheck and eight
  browser checks. Its promotion depends on the hosted evaluation route becoming
  available. These checks establish the entry workflow, not an external trial.


- October 5: process-shared pairing admission now limits all verifier instances
  to two active children per Python process, rejects saturation without a new
  process or waiting queue, and retains slots through repeated cancellation and
  reaping. Pilot inspection/evaluation/observation/authorization report retryable
  503, and durable workers preserve bounded retries. Runtime/HTTP checks: 124
  initially passed at 100% verifier coverage; worker tests: 24 passed at 100%.
  Actual current-profile positive/tampered pairing and two concurrent real
  pairings passed. Eighteen warmup/measured synthetic pairings on four cores
  accepted: two-child median request time 0.249 s and maximum sampled aggregate
  child RSS 152.0 MiB. This is pairing-only evidence, not service capacity or an
  SLA. Persisted/incremental inventories and further scale work remain open.

- October 5: pairing saturation was exercised through real PostgreSQL and the
  current authorization service with actual proofs. HTTP 503 creates no new
  record, receipt or nullifier consumption, and the same idempotency key can
  subsequently succeed. All 73 authorization/HTTP checks passed with 100%
  authorization-route coverage. Documentation: 115 checks and a production
  build passed; content: 25 checks and build passed. Full CI, approval and
  hosted guidance verification remain required for this change.

- October 6: the integration branch combines pairing #100, inventory/release
  #101 and evaluation #102 without changing their runtime implementations. API
  guidance retains both limits and removes a duplicate proving paragraph. The
  original pairing/inventory approvals reference older production revisions, so
  this combined source will receive fresh complete CI and review before merge.
  Existing PRs retain their evidence and will be superseded only after the new
  integration PR is established. Real testnet measurements, the wallet-profile
  decision and external evaluation/production assurance gates remain open.
