# Full test coverage work plan

Objective: full test coverage. Passing the existing tests alone is insufficient.
Measure all application source, inspect missed branches and skipped tests, and
exercise every supported test layer with its required local dependencies.

## Completion evidence required

- Python line and branch reports covering all `src` modules, including modules
  that tests never import. Report generated protobuf coverage separately when
  evaluating authored code; do not silently remove it from the inventory.
- TypeScript line, branch and function reports for every source workspace.
- Solidity instrumented coverage plus uninstrumented real-proof verification.
- Actual Circom witness and proof tests for supported profiles, including
  adversarial inputs. No generated development proving keys committed.
- PostgreSQL and local EVM integration tests, including restart, concurrency,
  rollback, expiry, authorization and tampering behavior.
- An inventory of every skipped/conditional test and evidence that each required
  environment-dependent path has run. Test count is not coverage percentage.
- CI runs the relevant tests and retains reproducible coverage evidence. Gates
  must not claim full coverage while untested behavior remains.

## Work sequence

1. Repair legacy PostgreSQL stores and obsolete fixtures; isolate each test's
   schema and include the suite in the existing PostgreSQL CI job.
2. Establish measured baselines with real local services and development proof
   artifacts, and inventory missing source/workspace coverage.
3. Add meaningful tests for uncovered behavior, prioritizing integrity,
   authorization and persistence. Fix defects those tests demonstrate.
4. Exercise CLI commands and external-component boundaries with controlled
   local dependencies. Include all source files in coverage denominators.
5. Run every supported layer, inspect residual branches/skips, and add CI
   reporting/gates that accurately reflect the achieved coverage.
6. Review, run remote checks, merge after clean checks, and verify merged main.

## Evidence so far (not completion)

- Legacy storage: 15 real PostgreSQL tests pass after tuple mapping, rowcount,
  timestamp conversion, fixture isolation and valid proof/nullifier setup fixes.
- SDK baseline: 372/400 lines (93%); 605/671 branches (90.16%).
- CLI baseline: 112/432 lines (25.92%); 115/238 branches (48.31%).
- Python: 1124 passed in the full run; the one skipped checkpoint test passed
  separately on its owned local EVM. Combined line coverage: 7161/8289 (86.39%);
  branch coverage: 1512/2046 (73.90%). Generated sources remain in this report.
- Expanded SDK tests: 187 passed, 382/400 lines (95.5%), 621/671 branches (92.54%).
- Expanded CLI tests: 51 passed, 144/432 lines (33.33%), 129/238 branches (54.2%).
- Solidity: 87 passed; 89.3% lines, 54.39% branches. A deployment child process
  previously overwrote instrumented artifacts; `--no-compile` repairs that
  measurement without omitting deployment tests.

## Next uncovered behavior to address

Python: checkpoint 155 combines the fresh full suite and explicit EVM paths:
8332/8332 statements and 2068/2068 branches (100%) across 143 source files.
Generated protobufs remain included and fully covered. No missed lines or
branches remain. The one pre-existing excluded line is unchanged. Full CI
execution of the new combined gate remains unverified.

CLI: source line/branch/function/statement coverage is now 100%, enforced by CI.
Keep the actual artifact/service acceptance tests alongside mocked boundary tests.

Solidity: checkpoint 132 measures full coverage: 387/387 lines, 275/275
statements, 402/402 branches and 88/88 functions. All 133 tests pass both
instrumented and with restored normal bytecode using both real proof bundles.
Coverage includes test harnesses and the BLS benchmark verifier. CI coverage
gating/artifact retention are configured; remote verification remains required.

These figures describe an intermediate worktree, not a released coverage claim.
The full goal remains open.

Docs: authored TS/TSX source unit coverage is 100% and gated, as is the shared
content package. Checkpoint 135 adds production-build Chromium acceptance tests
for all MDX pages on desktop/mobile, Mermaid rendering, navigation and content
APIs. Broader browser/deployment behavior and operational scripts still require
an explicit completion audit.


## Second checkpoint

- Python: 1152 passed in the full run, plus the checkpoint test passed separately
  on its owned EVM. Current combined coverage is 7363/8290 lines (88.82%) and
  1582/2050 branches (77.17%). SIWE service, auth HTTP routes, issuer registry
  and file audit mirror each have 100% measured line/branch coverage.
- Real SIWE tests exposed invalid nonce characters and equality-at-expiry bugs.
  Nonces now use 256 bits encoded as hexadecimal; expired nonces/sessions reject
  at the exact TTL boundary. HTTP tests verify real signing, protected access,
  replay rejection, session expiry and nonce rate limits.
- File audit tests exposed truncated tail hashing for records over 4 KB, blank
  tail handling, premature state advancement on failed writes and silent chain
  reset after read failures. These paths are repaired, and hash mismatch logging
  no longer includes caller-controlled values.
- Shared content: 11 tests, 106/106 lines, 67/67 branches, 16/16 functions.
  CI now runs this package's tests with a 100% coverage gate and retains reports.
- CLI: 89 tests, 329/432 lines (76.15%), 201/238 branches (84.45%). New tests
  exercise packaged help and signal explanations, rendering, diagnostics,
  interactive recipes and history/counterparty process lifecycle handling.

Remaining integrity investigations include prover subprocess timeout/rejection
handling and legacy audit-log newline compatibility. A 100% module coverage result does
not by itself prove these behavioral properties. The full objective remains open.


## Third checkpoint

- CLI: 141 tests pass with 432/432 lines, 238/238 branches, 59/59 functions and
  476/476 statements. The coverage command now requires 100% for each metric.
  Tests include actual entrypoint dispatch, private-input timeout cleanup,
  policy/investigation schemas, resumed queue completeness, proof file selection,
  verification exit codes and development-labelled demo export hashes.
- File audit: synchronized independent processes and interleaved instances now
  extend one chain. Each operation uses a Portalocker file lock, reads the current
  predecessor from the locked handle, and flushes/fsyncs before release. Lock
  contention and incomplete trailing records fail without an unlocked append.
  The local filesystem concurrency tests verify all 48 records and their links.
- PostgreSQL audit: head selection and insertion now share one transaction and
  table lock. Verification checks sequence continuity and predecessor linkage,
  rejecting rehashed splices as well as individually invalid hashes. Real database
  concurrency and tampering regressions pass; the storage suite has 18 tests.
- Both audit modules retain 100% measured source line/branch coverage.
- Full Python run: 1159 passed, with the one checkpoint test separately passing
  on an owned local EVM. Combined coverage is 7372/8299 lines (88.83%) and
  1589/2056 branches (77.29%). No generated source was removed from the denominator.

File-lock API reference: [Portalocker quickstart](https://portalocker.readthedocs.io/en/latest/quickstart.html).
Locks coordinate cooperating writers; these tests cover the local filesystem.
The remaining Python, SDK, contracts, docs and operational-script requirements
still need completion and final merged-main verification.

## Fourth checkpoint in progress

- Keyring rotation, legacy CRLF audit append compatibility and real chain ABI/signing
  regressions pass in focused tests. These changes still need the next full
  PostgreSQL/artifact regression and combined coverage measurement.
- Legacy verification now follows SnarkJS's exit status rather than searching
  stdout for `OK`. Both entry points share verification-key-only behavior, private
  temporary directories and owned subprocess cleanup. Timeout/cancellation reaps
  children before deleting files; POSIX cleanup includes the process group.
  `npx --no-install` prevents implicit package installation. Tool output is discarded
  because it may include witness data.
- Eleven focused verifier/process tests pass with 100% measured line and branch
  coverage of the standalone verifier and process helper. Tests include actual
  child timeout/cancellation, cancellation during creation, spawn failure,
  platform cleanup and an already-exited process race. The actual installed
  SnarkJS also accepts the committed development proof and rejects altered public
  signals through both entry points (one integration test, four CLI executions).
- Proof generation still uses the old subprocess lifecycle and requires its own
  cleanup, failure and actual round-trip tests. The verifier coverage result does
  not establish full prover coverage or completion of the overall goal.
- Broader unit regression: 950 tests pass. Ruff, diff whitespace checks and REUSE
  licensing checks pass. Full service/artifact coverage totals are not yet refreshed.

## Fifth checkpoint

- Proof generation now shares owned process cleanup with verification and keeps
  input, witness and output files inside a private temporary directory. Tests
  reproduced private-input leakage from witness/prover stderr; errors now retain
  stage and exit status without tool output. Real child tests cover timeout and
  cancellation at each stage, alongside missing artifacts and malformed output.
- Twenty-two focused tests pass with 100% measured line/branch coverage of the
  legacy prover, standalone verifier and subprocess helper. Actual SnarkJS tests
  also generate a fresh proof from cached development artifacts, accept it and
  reject changed public signals. The existing development-circuit CI script now
  runs these integration tests with its freshly generated legacy artifacts.
- SDK: 197 tests pass; 400/400 source lines and 89/89 functions are covered.
  CI's existing coverage command now enforces 100% lines/functions. Statements
  remain 497/516 (96.31%) and branches 643/671 (95.82%); the SDK is not fully
  covered yet. New tests exercise authorization request/receipt binding,
  observation identity matching, cohort validation, DNS answer retention and
  malformed operator egress configuration.
- TypeScript SDK build passes. Full Python/PostgreSQL/artifact coverage is being
  refreshed; the separate local EVM checkpoint test passed.

- Full Python run: 1200 passed; the one skipped checkpoint passed separately on
  the owned local EVM. Combined coverage is 7516/8295 lines (90.61%) and
  1628/2060 branches (79.03%). Generated modules remain in the denominator.
  The local PostgreSQL server was stopped after verification. Ruff, whitespace
  and REUSE checks pass. Full coverage remains incomplete; subprocess coverage
  capture, gRPC/API lifecycle branches, SDK branches, Solidity and docs/scripts
  are still required before final CI/merge verification.

## Sixth checkpoint

- Coverage now enables the installed coverage.py subprocess patch. An isolated
  test invoking Python CLI modules (without importing them in the parent) records
  execution of their entrypoints in the JSON report. This fixes the measurement
  gap for child-process CLI acceptance tests; the full run is being refreshed.
- gRPC: tests reproduced a missing protobuf Error class in both server error
  handlers, exception logs containing synthetic private input, and an unsupported
  RPC returning UNKNOWN rather than UNIMPLEMENTED. The handlers now use the
  actual errors protobuf, minimize logs and explicitly abort unsupported address
  confirmation. Generated protobufs were not edited.
- Seventeen gRPC tests pass. The bridge measures 140/140 lines and 18/18 branches.
  Tests exercise actual TLS/mTLS servers with sealed unary and streaming messages,
  key exchange, unsupported RPC status, and rejection without a client certificate,
  plus scoped protocol responses, client dispatch and channel cleanup.
- SDK: 206 tests pass; coverage is 400/400 lines, 89/89 functions, 506/517
  statements (97.87%) and 654/671 branches (97.46%). Stream cleanup now releases
  the reader lock even if cancellation fails. Added tests cover oversized streams,
  escaped canonical byte limits, malformed pages/signals and independent pairing
  and threshold rejection. Real proof vector verification remains in the suite.
- SDK build, Ruff, whitespace and REUSE checks pass. The local-EVM checkpoint
  test passes with subprocess measurement enabled. Completion remains unproven
  until all outstanding source/workspace/test-environment requirements are met.

- Full Python regression: 1208 passed, plus the isolated EVM checkpoint passed.
  Combined source coverage including child processes and generated modules is
  7663/8295 lines (92.38%) and 1650/2060 branches (80.10%). PostgreSQL was stopped
  after verification. Reports are retained as `full-coverage-combined-fifth.json`
  in the local evidence directory. API lifecycle and proof-route error/persistence
  paths are the largest remaining authored Python gaps.

## Seventh checkpoint

- API lifecycle tests reproduce skipped database cleanup on serving failure and
  stale application state after normal shutdown. Lifespan now clears the state
  reference and closes its owned database in `finally`, including cancellation
  and connection failure. Key validation and actual CORS preflight tests cover
  accepted key encodings, missing/short keys and wildcard removal.
- The proof generation sanctions check previously called `run_until_complete`
  inside the running API event loop. It is now asynchronous and awaited by the
  route. Tests exercise fresh/stale boundaries, missing roots, cached retries,
  missing/revoked credentials and required originator information.
- An exact-expiration credential regression also failed before the fix. The
  route now rejects at `now >= expires_at`, before recipient discovery/proving.
- API/lifecycle/proof-route/compliance regression: 103 tests pass. API main source
  measures 78/78 lines and 14/14 branches. The focused proof-route report still
  misses 46 lines and is not a whole-suite coverage claim. Ruff and REUSE pass.
- Full Python/PostgreSQL/artifact totals remain the prior sixth checkpoint until
  a fresh combined run. Remaining proof-route work includes durable writes and
  app-specific database access (the route currently imports the global app),
  verification failure handling and other error branches. The full objective
  remains active across Python, SDK, contracts, docs and operational scripts.

## Eighth checkpoint

- A real HTTP regression using a separately created app showed proof generation
  reading the module-global app's database and returning a missing-credential
  error instead of its own cached result. The route now receives the HTTP Request
  and uses that request's application state. The obsolete global-app accessor
  was removed, and affected test boundaries were updated.
- Verification exception logging exposed synthetic untrusted input. Logs now
  retain a fixed diagnostic without exception text. Tests cover malformed/short
  public signals, failed pairing and malformed/unavailable chain observations;
  absent evidence remains unverified rather than a successful jurisdiction match.
- API/lifecycle/proof-route/compliance regression: 114 tests pass. The focused
  proof route measurement misses 32 lines, primarily durable writes and remaining
  setup/error handling. Ruff, whitespace and REUSE checks pass. Whole-suite
  coverage percentages still refer to the last combined run, not this subset.
- Durable proof generation needs real PostgreSQL acceptance, including failure
  rollback and retries, before declaring its persistence paths covered. The full
  objective and all remaining workspaces remain open.

## Ninth checkpoint

- Real PostgreSQL generation exposed byte fields passed directly to JSON when
  calculating the retry digest. Ciphertext and nonce now use explicit base64
  encoding in that digest. No decrypted payload is added to persistence.
- Injected audit failure then demonstrated partial commits. Database.transaction
  now supplies one owned connection to cooperating stores. The route writes
  credential, proof, nullifier, retry record and audit together, rechecking retries
  under a transaction advisory lock. A conflicting nullifier rejects and rolls
  back the new proof rather than silently ignoring the conflict.
- Four new real PostgreSQL tests verify generation/retry, rollback followed by
  successful retry, synchronized concurrent retries and nullifier conflict.
  The dedicated PostgreSQL CI job includes this test file.
- Storage/API focused regression: 96 tests pass. The proof route has 20 missed
  lines in this focused measurement. Ruff, whitespace and REUSE pass; overall
  percentages await a fresh full run after the recent API changes.
- These persistence tests mock the cryptographic boundary. The legacy API's
  generated circuit-input layout still needs an actual-artifact acceptance test;
  passing database tests does not establish valid real proof generation. Full
  coverage remains active for that path and all other outstanding requirements.

## Tenth checkpoint

- A new API test invokes actual SnarkJS with matching development artifacts and
  explicit depth-10 issuer/depth-20 sanctions witnesses. It reproduced outdated
  signal names, array-wrapped scalars, missing Merkle paths, an empty replacement
  issuer registry and decimal hashes interpreted as hex in API witness assembly.
- The route now consumes its configured issuer registry and both witnesses, uses
  the existing circuit's scalar names, preserves field integers as decimal strings
  across JavaScript JSON parsing and captures one timestamp/expiry pair for the
  proof and stored metadata. No circuit, key or verifier was changed.
- Actual API proof generation and verification pass, including matching public
  roots and timestamp metadata. The existing development-circuit CI script now
  includes this test. API/compliance regression: 103 tests pass.
- This test supplies matching fixed-depth witness providers. Ordinary dynamic-depth
  registry/tree builders still need compatibility checks before claiming that
  their default artifacts can feed the fixed-depth legacy circuit. Issuer trust
  must remain operator-configured; credentials must not auto-enroll their issuers.
- SDK: 211 tests pass; 400/400 lines, 89/89 functions, 513/517 statements (99.22%)
  and 664/671 branches (98.95%). Added coverage includes default discovery input
  rejection, malformed profiles, noncanonical key encoding, all-zero agreement
  defense and mixed-cohort denominators. Seven branches remain to inspect.
- SDK build, Ruff, whitespace and REUSE pass. Full Python coverage is being
  refreshed with all configured services/artifacts; the separate local-EVM
  checkpoint test passed. This remains progress, not full-goal completion.

- Full Python run: 1246 passed, plus the separate local-EVM checkpoint passed.
  Combined coverage is 7768/8316 lines (93.41%) and 1681/2062 branches (81.52%),
  including child processes and generated modules. PostgreSQL was stopped after
  verification. The next largest authored gaps include sanctions registry logic,
  pilot proof routes, policy model validation and the in-memory SAR audit log.

## Eleventh checkpoint

- In-memory SAR audit tests reproduced mutable retained entries exposed through
  append/read/transaction results, replacement of explicit epoch zero, an empty
  transaction filter returning all records, and acceptance of rehashed sequence
  gaps. The APIs now return detached entry copies, preserve explicit timestamps,
  distinguish None from empty references and verify contiguous sequence numbers.
- The existing hash format is preserved. Documentation now accurately states
  that it binds payload digests/links/sequences, not entry metadata or an external
  chain anchor. This is an in-memory legacy audit structure, not encrypted storage.
- Eight new audit tests pass; the affected API/compliance regression totals 110
  passing tests. The SAR audit module measures 52/52 lines and 8/8 branches.
  Ruff, whitespace and REUSE pass. Overall percentages remain those of the last
  combined full run until refreshed; this focused result is not full completion.
- Fixed-depth registry/artifact compatibility, remaining Python validation
  branches, SDK's seven branches, Solidity, docs and operational script coverage
  remain part of the active objective.

## Twelfth checkpoint

- Both registry builders now accept an explicit depth. Zero-subtree extension
  preserves real authentication paths without allocating the full fixed-size
  leaf array. Invalid depth and over-capacity requests reject; capacity tests
  verify that previous tree state remains intact. Defaults preserve prior roots.
- The legacy API's operator-managed issuer registry uses depth 10. The sanctions
  build script accepts `--depth 20` for the corresponding legacy circuit profile;
  build-script version is 1.2.0. Native and operational builder roots agree, and
  serialized sparse layers reload with the correct authentication paths.
- The actual API circuit test now uses real issuer/sanctions builders and a real
  sanctions artifact reload instead of supplied witness mocks. Actual proof
  generation/verification, roots, verification key and timestamps pass.
- Fixed-depth/helper/registry/API/compliance regression: 105 tests pass. The new
  extension helper measures 17/17 lines and 8/8 branches in the focused report.
  The CLI exposes the depth option and rejects invalid depths before building.
  Ruff, whitespace and REUSE pass. Full combined coverage remains to be refreshed.
- Only synthetic local trees were built during tests. Selecting a different
  depth changes the root; operators must publish/relay the chosen root consistently
  on deployed chains. Existing published roots and proving artifacts were not changed.
- Remaining sanctions work includes artifact validation and field-range boundary
  behavior. Other Python, SDK, Solidity, docs and operational-script coverage
  requirements remain active; this checkpoint does not establish full coverage.

## Thirteenth checkpoint

- Artifact tests reproduced loss of declared depth during reload/rebuild and
  acceptance of invalid depth values. Loading now validates and retains the
  artifact's depth, preserving the selected root/profile when rebuilt.
- Tests also reproduced gap witnesses whose neighbors did not bracket the query.
  Those cases now reject instead of returning an unusable witness. The unreachable
  empty-leaf branch was removed: two sentinels are always inserted before it.
- Sixteen artifact tests cover missing/malformed files, stale-age boundaries,
  metadata-only legacy files without witness layers, invalid depths, reload/root
  preservation and absent bracketing leaves. The affected registry/builder/real
  API proof/compliance regression passes 65 tests. The sanctions registry measures
  113/113 lines and 36/36 branches; Ruff, whitespace and REUSE checks pass.
- This does not establish authenticity of a loaded root or solve the legacy
  circuit's 252-bit key range restriction. Whole-tree consistency, configured
  root trust and remaining profile boundary behavior still require review/tests.
  Full combined coverage and outstanding Python/SDK/contracts/docs/scripts work
  remain part of the active objective.

## Fourteenth checkpoint

- Added policy trust-boundary tests for malformed/non-ASCII source references,
  source credentials/fragments, invalid review intervals, deployment IDs,
  revision links, rule operator/threshold mismatches, duplicate or missing source
  references, bounded inventories and duplicate current pins. Accepted HTTPS
  references and all four coherent rule operators are also exercised.
- The existing validators reject these inputs correctly; no production model
  changes were necessary. The policy/evaluator/diff regression passes 87 tests.
  The policy model measures 127/127 statements and 60/60 branches in the focused
  report (`policy-validation.data`). Ruff and whitespace checks pass.
- This is module-level evidence. Overall Python coverage still requires a fresh
  combined service/artifact run, and the remaining SDK, contracts, docs, scripts
  and publication requirements remain open.

## Fifteenth checkpoint

- Refreshed the complete Python run with PostgreSQL, both real proving profiles
  and policy CLI acceptance enabled: 1318 passed, one checkpoint test skipped.
  That checkpoint passed separately on its owned local EVM. Combined same-source
  coverage is 7850/8343 lines (94.09%) and 1733/2076 branches (83.48%), including
  subprocesses and generated protobuf modules. PostgreSQL was stopped afterward.
  Reports: `full-coverage-python-seventh.log`,
  `full-coverage-checkpoint-seventh.log`, `full-coverage-combined-seventh.json`.
- Added the docs workspace's first test/coverage commands and 47 tests against
  real catalogue data and NextResponse. Every catalogue entry is served and
  missing/traversal-like/prototype-name slugs return bounded JSON 404 responses;
  successful and error responses retain the expected cache and content headers.
  All four content API handlers measure 100% in every coverage metric.
- Explicit Oxc JSX transformation prevents the layout from being silently
  discarded by coverage parsing. All authored TS/TSX modules are included:
  21/26 lines (80.76%), 4/6 functions (66.66%) and 6/6 branches. Layout/MDX wrapper
  execution and actual MDX/browser rendering remain unproven by this report.
- Docs tests, standalone typecheck and production build pass; the build generated
  all 21 static pages. CI runs and uploads the docs coverage report. The README
  documents test scope, and generated TypeScript build metadata is ignored.
  REUSE and whitespace checks pass. No coverage PR has been published yet.
- Largest authored Python line gaps now include pilot proof/discovery routes,
  pilot verifier/storage and evidence export. SDK residual branches, Solidity,
  docs rendering, operational scripts and the final review/merge/main verification
  remain outstanding. These results do not establish full repository coverage.

## Sixteenth checkpoint

- Expanded pilot-verifier tests from 25 to 52 cases. New checks cover byte-only
  proof input, exact runtime pins, empty/oversized/FIFO bundles, absolute executable
  Node configuration, invalid timeout values, malformed/nonzero runtime responses,
  negative pairing results and runtime removal after configuration.
- Controlled real-child tests cover cancellation during shielded process creation
  and a simulated ProcessLookupError during process-group cleanup. Both verify
  reaping and temporary-directory removal. Runtime fixtures test transport and
  lifecycle; existing real Groth16 integration evidence remains separate.
- All 52 tests pass; the verifier measures 117/117 statements and 22/22 branches
  (`pilot-verifier-complete.log` and `.data`). Ruff and whitespace pass. No
  production verifier changes were necessary. The first cleanup-race fixture
  exited early because it omitted the stub verifier; that fixture was corrected
  to keep verification pending before checking timeout cleanup.
- Overall percentages remain the fifteenth checkpoint's full-run results until
  refreshed. Remaining Python, SDK, Solidity, docs rendering, operational scripts
  and final publication/review requirements remain open.

## Seventeenth checkpoint

- Added 40 focused evidence-export tests using real X25519/HPKE and explicitly
  synthetic records. Offline opening rejects envelope shape/version changes,
  recipient substitution and decrypted scope mismatches; recipient configuration
  rejects invalid validity intervals and low-order keys.
- Controlled read-only storage fixtures exercise exact pinned records, missing
  receipts/proofs/rows/chunks, changed rows, invalid reference/configuration/chunk
  counts, captured configuration digest/size mismatches and output size limits.
  Recipient expiry and tenant isolation reject. Optional timestamp bytes are
  retained without asserting timestamp signature verification or timing authority.
- All 40 tests pass; `src/services/evidence_export.py` measures 93/93 statements
  and 42/42 branches (`evidence-export-boundaries.log` and `.data`). Ruff and
  whitespace checks pass. No production changes were necessary. Storage fixtures
  here isolate failure paths; existing real PostgreSQL tests remain the separate
  persistence evidence. Whole-repository figures are not refreshed by this run.
- Outstanding scope remains the other Python gaps, SDK branches, Solidity,
  docs rendering, operational scripts and review/CI/merge/main verification.

## Eighteenth checkpoint

- Added discovery publisher HTTP tests for optional metadata, configured exchange
  endpoints and chain-list parsing. Real matching X25519 private/public keys are
  accepted. Invalid domains/DIDs, chains, endpoints and malformed/noncanonical
  keys produce a generic HTTP 503 without returning configuration details.
- All 112 discovery unit tests pass. The publisher measures 69/69 statements and
  22/22 branches (`discovery-publisher.log` and `.data`). Ruff and whitespace pass;
  no production changes were needed. These ASGI tests exercise the publisher,
  while outbound TLS/SSRF behavior remains covered by the separate transport suite.
- Whole-repository percentages remain the last full combined report. Remaining
  Python, SDK, Solidity, docs/browser, operational-script and publication work
  is still required before claiming full test coverage.

## Nineteenth checkpoint

- Added 38 ASGI tests for observation read/report/list routes. They verify invalid
  and duplicate-key JSON rejection, private-body-only pagination selectors,
  unavailable databases/encryption configuration, bounded storage-error responses,
  missing observations and successful service result forwarding.
- Each route requires both policy-read and evidence-decrypt roles, including for
  a tenant administrator; denied requests never call the storage service. These
  tests override authentication with explicit principals and mock service results,
  while the existing JWT/PostgreSQL suites cover those separate boundaries.
- All 38 tests pass; Ruff and whitespace checks pass. No production changes were
  required. The focused report covers all three observation read handlers and
  shows 103/164 statements for the complete pilot-proof route module; inspect,
  evaluate and observe paths remain outside this focused invocation. Do not
  interpret that partial report as repository-wide coverage or a regression.
- Remaining route failure paths and the broader Python/SDK/contracts/docs/scripts
  and publication requirements remain active.

## Twentieth checkpoint

- Expanded the observation route suite to 68 tests with pilot inspection target
  isolation, invalid target/configuration/database/key rejection, private proof
  validation and bounded service errors. Invalid input is rejected before operator
  configuration is accessed; targets from another tenant return unavailable.
- Evaluation/observation handler tests cover missing fact trust, missing enrollment,
  rejected facts/runtime failures and the stable 409 idempotency-conflict response.
  These isolate handlers with prepared service stubs; actual trust, pairing and
  persistence remain the responsibility of their existing integration suites.
- All 68 tests pass. The focused pilot-proof module report covers 162/164 statements
  and 32/32 branches. Its two missing statements are inspect/evaluate success
  response construction, already exercised in the full database/artifact suite;
  a fresh combined report remains necessary before updating overall figures.
  Ruff and whitespace pass; no production code changed.
- Full coverage remains incomplete across other Python code, SDK residual branches,
  Solidity, docs/browser rendering, operational scripts and publication checks.

## Twenty-first checkpoint

- Added 45 publication-history tests for coherent included/unestablished states,
  contradictory inclusion/confirmation/execution/registry-effect claims, numeric
  bounds and forbidden authorization/resubmission claims. Invalid history cursors,
  clocks, intent bindings and policy digests reject before database access.
- The combined publication validation/reconciliation/journal regression passes
  93 tests, including all 16 real PostgreSQL integration cases. History module
  coverage is 105/109 statements and 34/38 branches (95% combined metric), with
  remaining gaps at encrypted identity mismatch, retained transaction mismatch,
  invalid history cursor and incomplete chain rejection. Evidence is recorded in
  `publication-history-regression.log` and `.data`; PostgreSQL was stopped afterward.
- Ruff and whitespace pass. No production changes were required. The remaining
  history integrity paths and broader Python/SDK/contracts/docs/scripts and final
  publication requirements remain open; this is not full coverage completion.

## Twenty-second checkpoint

- Added four PostgreSQL integrity tests for missing publication intent, unknown
  history cursor, SQL/encrypted sequence mismatch, authenticated sequence gaps
  and a cursor whose next retained row skips its requested sequence.
- Corruption is limited to isolated synthetic test schemas. The gap test re-seals
  a valid encrypted/digested row with sequence 2 as the first row, proving that
  history checks enforce continuity beyond ciphertext authentication. Rejections
  leave the publication unbroadcast.
- The related regression passes 97 tests, including 20 PostgreSQL cases. History
  measures 109/109 statements and 38/38 branches in
  `publication-history-complete.log`/`.data`. Ruff and whitespace pass. PostgreSQL
  was stopped after verification; no production changes were needed.
- Whole-repository completion remains unproven. Other Python gaps, SDK branches,
  Solidity, docs/browser rendering, operational scripts and final review/merge
  evidence remain required.

## Twenty-third checkpoint

- Added 17 transfer-schema tests covering empty/duplicate/oversized catalogues,
  VASP/self-hosted identity consistency, zero wallets/amounts/valuations, valuation
  asset mismatch, catalogue digest mismatch, invalid deployment chain/address and
  missing evaluated-proof references. Catalogue ordering/digest remain independent
  of input order, and exposed asset definitions remain immutable.
- The transfer/policy regression passes 121 tests. Transfer models and catalogue
  logic measure 200/200 statements and 54/54 branches in
  `transfer-schema-complete.log`/`.data`. Ruff and whitespace pass. No production
  changes were required; these validations do not establish price truth, issuance
  authority or compliance beyond the explicitly checked record constraints.
- Full repository coverage remains incomplete across remaining Python paths,
  SDK branches, contracts, docs/browser rendering, operational scripts and final
  review/CI/merge verification. Overall percentages require a fresh full run.

## Twenty-fourth checkpoint

- Added 22 artifact validation tests for runtime modes, canonical trust pins,
  unavailable/file/symlink roots, strict JSON encoding/constants/limits and files
  changed after the initial metadata snapshot. Real-file growth, truncation and
  same-size rewrites deterministically reject; tests do not depend on race timing.
- The artifact/verifier regression passes 99 tests. Artifact inspection measures
  159/159 statements and 48/48 branches (`pilot-artifacts-complete.log`/`.data`).
  Ruff and whitespace pass. No production changes or proving artifacts changed.
- These tests cover loader trust boundaries and runtime lifecycle, not ceremony
  legitimacy or source-to-binary reproducibility. Full repository coverage still
  requires remaining Python, SDK, Solidity, docs/browser, scripts and final
  publication verification work; the latest full-run percentages remain unchanged.

## Twenty-fifth checkpoint

- Added 12 encrypted-record tests for non-object inputs, missing active-key
  inventory, authenticated noncanonical JSON, malformed decrypted JSON and a
  content tag inconsistent with otherwise valid AEAD ciphertext. Fixtures contain
  synthetic data and use real AES-GCM; internal key/AAD helpers deliberately
  construct authenticated invalid rows to exercise post-decryption validation.
- All 21 cipher tests pass. RecordCipher measures 60/60 statements and 14/14
  branches (`pilot-cipher-complete.log`/`.data`). Ruff and whitespace pass.
  No production changes were required. Record-size limits belong to callers and
  database constraints, not this cipher's API, and remain separate test scope.
- Other Python storage/lifecycle gaps, SDK branches, Solidity, docs/browser,
  operational scripts and final publication checks still prevent a full coverage
  completion claim. Full-suite totals have not been refreshed in this checkpoint.

## Twenty-sixth checkpoint

- Added six ASGI request-body tests for exact chunked limits, empty uploads,
  over-limit early termination, deadline cancellation, client disconnect and
  caller cancellation. The timeout test checks the configured ten-second value
  and shortens only the test deadline while retaining real asyncio cancellation.
- The upload/route regression passes 74 tests. The bounded upload helper measures
  13/13 statements and 4/4 branches (`private-request-body.log`/`.data`). Ruff and
  whitespace pass. No production changes were required. Partial private bodies
  are not returned on disconnect, cancellation or limit/deadline failures.
- Remaining Python, SDK, Solidity, docs/browser, operational-script and final
  review/publication requirements still prevent full repository completion.

## Twenty-seventh checkpoint

- Added nine policy evaluator tests for exact safe-integer clocks, positive fact
  intervals, replay before effective intervals, unresolved applicability despite
  a matched allow rule, and verified-fact enrichment preserving external scope
  while rejecting duplicate predicates.
- The policy/model/diff regression passes 96 tests. Evaluator coverage is 107/107
  statements and 48/48 branches (`policy-evaluator-boundaries.log`/`.data`). Ruff
  and whitespace pass; no production changes were required. These are deterministic
  policy checks, not evidence of legal completeness or authority to consume proofs.
- Full repository coverage remains incomplete across other Python modules,
  SDK branches, Solidity, docs/browser, scripts and final publication checks.

## Twenty-eighth checkpoint

- Added 18 fact-approval tests for signing-time boundaries, authority scope
  ambiguity, forbidden derived predicates, mismatched real Ed25519 signing keys,
  bounded authority/approval inventories and independently authenticated tenant
  mismatch. Existing signature, freshness, compromise and conflict tests remain.
- The fact/evaluator regression passes 65 tests. Fact approval measures 102/102
  statements and 30/30 branches (`fact-approval-complete.log`/`.data`). Ruff and
  whitespace pass; no production changes were required. Signatures establish the
  configured attestor's claim, not factual truth or legal sufficiency.
- Remaining Python, SDK, contracts, docs/browser, operational scripts and final
  publication/verification work keep the full coverage goal active.

## Twenty-ninth checkpoint

- Added six comparison tests for incompatible tenant/chain/registry/jurisdiction/
  catalogue scope and duplicate case IDs over distinct valid transfers. The
  duplicate-case assertion was corrected to account for Pydantic's validation
  wrapper; production validation already rejected the input correctly.
- All 15 policy-diff tests pass, including real stdin CLI and authenticated HTTP
  checks. Diff coverage is 81/81 statements and 10/10 branches, with subprocess
  coverage captured (`policy-diff-complete.log`/`.data`). Ruff and whitespace pass.
  No production changes were needed.
- Remaining repository scope includes other Python paths, SDK branches, Solidity,
  docs/browser rendering, scripts and final CI/review/merge verification. The full
  coverage objective remains active and overall percentages await a fresh run.

## Thirtieth checkpoint

- Added nine canonical-encoding tests for malformed commitment domains and the
  serialized 64-KiB boundary. Quote-heavy records pass the structural budget but
  expand during JSON escaping; tests verify 65535/65536-byte acceptance and
  65537-byte rejection without changing production limits.
- All 71 transfer/canonical tests pass. Canonical encoding measures 44/44
  statements and 24/24 branches (`canonical-complete.log`/`.data`). Ruff and
  whitespace pass; no production changes were needed.
- This restricted ASCII record encoding remains distinct from general JSON
  canonicalization. Other Python gaps and the SDK/contracts/docs/scripts plus
  publication requirements still leave full repository coverage incomplete.

## Thirty-first checkpoint

- Added nine recipient-authority and software-encryption tests. Invalid canonical
  recipient identities/intervals and empty/duplicate/oversized key inventories
  reject. Real AES-GCM tests show stable configured HKDF derivation, separation
  between deployment salts and envelope contexts, and legacy fallback warnings.
- All 54 related tests pass. Software encryption and pilot envelope modules
  together measure 85/85 statements and 16/16 branches (`sar-boundaries.log`/`.data`).
  Ruff and whitespace pass. No production changes were required; configuring or
  changing live salts was not part of this test-only work.
- Other Python gaps, SDK branches, Solidity, docs/browser, scripts and final
  CI/review/merge verification remain open. Overall figures still require refresh.

## Thirty-second checkpoint

- Confirmed principal authorization already has full measured line/branch coverage
  in the prior report, then added 15 root-snapshot tests for invalid audiences,
  validity intervals, predecessor links, issuer identities, authority inventories
  and scope-ID stability across revisions with deployment separation.
- All 50 snapshot/pilot-root tests pass. Root snapshots measure 120/120 statements
  and 40/40 branches (`root-snapshot-complete.log`/`.data`). Ruff and whitespace
  pass; no production changes were required. Real signature and current-head
  checks remain part of the existing suite; snapshot signatures alone do not
  establish current-head authority.
- Remaining Python, SDK, Solidity, docs/browser, scripts and final publication
  checks still prevent a full repository completion claim.

## Thirty-third checkpoint

- Added 11 valuation-approval tests for signatures outside quote validity,
  invalid authority intervals, duplicate asset/source scopes, bounded authority
  inventories and digest binding to signature time without changing quote data.
- All 33 valuation tests pass. Valuation approval measures 91/91 statements and
  24/24 branches (`valuation-approval-complete.log`/`.data`). Ruff and whitespace
  pass; no production changes were needed. Authentication of a signed quote does
  not independently establish pricing truth.
- Full repository coverage remains incomplete across remaining Python paths,
  SDK branches, contracts, docs/browser, scripts and final publication checks.

## Thirty-fourth checkpoint

- Added seven information-approval tests for invalid signing intervals, invalid
  authority validity, duplicate source scopes and empty/duplicate/oversized key
  inventories. Existing real signature, payload binding and rotation cases pass.
- All 29 tests pass. Information approval measures 80/80 statements and 12/12
  branches (`information-approval-complete.log`/`.data`). Ruff and whitespace pass;
  no production changes were required.
- Full repository coverage remains incomplete across remaining Python behavior,
  SDK branches, Solidity, docs/browser rendering, scripts and final publication
  checks. This module result does not update the whole-suite coverage figures.

## Thirty-fifth checkpoint

- Added six decision-attestation tests for invalid authority intervals, missing/
  duplicate/excessive key inventories and mismatched real Ed25519 signing keys.
  Rejection leaves the receipt unchanged; existing historical expiry, compromise,
  signature and scope cases continue to pass.
- All 16 tests pass. Decision attestation measures 75/75 statements and 10/10
  branches (`decision-attestation-complete.log`/`.data`). Ruff and whitespace pass;
  no production changes were needed. Operator-clock signatures remain separate
  from independently trusted timestamp evidence.
- Remaining Python, SDK, Solidity, docs/browser, scripts and publication checks
  still leave the full repository coverage goal incomplete and active.

## Thirty-sixth checkpoint

- Added 23 credential tests for canonical issuer identity, failed screening,
  bounded list-based membership paths and exact direction types, evaluation-time
  boundaries and wrong holder secrets. Synthetic roots are used only for early
  validation tests; existing actual Circom witness checks remain in the same run.
- All 52 credential tests pass. Credential encoding/witness preparation measures
  76/76 statements and 24/24 branches (`credential-boundaries.log`/`.data`). Ruff
  and whitespace pass. No production or proving-artifact changes were required.
- Remaining Python, SDK, Solidity, docs/browser, operational scripts and final
  publication checks leave full coverage incomplete. Overall figures await refresh.

## Thirty-seventh checkpoint

- Added 14 discovery-profile tests for bounded string targets, X25519 coordinate
  range, document/version/capability shapes and base64 padding-bit aliases that
  decode to identical bytes but are not canonical encodings.
- All 126 discovery tests pass. Profile coverage is 95/96 statements and 45/46
  branches (`discovery-profile-boundaries.log`/`.data`). The remaining DID
  reconstruction inequality at line 77 appears unreachable after earlier
  authority/path validation; that requires explicit review, not an unsupported
  100% claim or removal solely to improve metrics. Ruff and whitespace pass.
- No production changes were needed. Other Python, SDK, Solidity, docs/browser,
  scripts and final review/publication requirements remain open.

## Thirty-eighth checkpoint

- Added 13 enrollment/wallet model tests for consent validity relative to issuance
  and credential expiry, zero audiences/nonces, challenge issuance outside
  credential validity, exact attestation TTL/identity and extension intervals.
  An initial enrollment fixture-index error in the new tests was corrected.
- All 40 tests pass, including existing real EOA signature and staged Circom
  witness checks. Both protocol modules measure 146/146 statements and 44/44
  branches combined (`wallet-model-boundaries.log`/`.data`). Ruff and whitespace
  pass; no production changes or proving artifacts changed.
- Remaining Python, SDK, Solidity, docs/browser, scripts and final publication
  evidence keep the full repository coverage objective active and incomplete.

## Thirty-ninth checkpoint

- Added six discovery-client tests for malformed/non-object/oversized operator
  egress configuration and the public cache-clear helper. Invalid configuration
  neither replaces the last valid client nor returns its cached key; explicit
  clearing causes a new fetch.
- All 132 discovery tests pass. Client coverage is 59/59 statements and 16/16
  branches (`discovery-client-complete.log`/`.data`). Ruff and whitespace pass;
  no production changes were required. These tests mock document fetches; the
  existing transport suite separately covers real local TLS/egress behavior.
- Remaining Python, SDK, Solidity, docs/browser, scripts and publication checks
  keep full repository coverage incomplete. Overall reports still need refresh.

## Fortieth checkpoint

- Added six discovery transport tests for ordered system-DNS deduplication,
  rejection of changed host/port before resolution, and non-JSON numeric constants
  returned over actual local HTTPS. Existing TLS/SSRF/redirect/deadline tests pass.
- All 154 discovery tests pass. Transport measures 82/82 statements and 34/34
  branches (`discovery-transport-complete.log`/`.data`). Ruff and whitespace pass;
  no production changes were needed. Controlled DNS fixtures do not contact public
  services; HTTPS tests use an owned local server and certificate.
- Full repository coverage remains incomplete across other Python paths,
  SDK branches, Solidity, docs/browser, scripts and final publication checks.

## Forty-first checkpoint

- Added seven bounded file-input tests for exact byte limits, empty input,
  oversized input, FIFO rejection without a writer, symlinks and missing files.
  Added four hybrid-payload envelope-version indicator cases; the indicator is
  explicitly tested as version detection, not cryptographic validation.
- All 34 focused tests pass, including existing nonce and TRP/TRISA serialization
  tests. File input and hybrid payload measure 38/38 statements and 6/6 branches
  combined (`file-hybrid-complete.log`/`.data`). Ruff and whitespace checks pass.
  No production changes were needed.
- Full repository coverage remains incomplete. A fresh full Python run is needed
  to consolidate recent additions before addressing remaining cross-workspace
  gaps and publication checks.


## Forty-second checkpoint

- Refreshed the complete Python suite with PostgreSQL, explicit development
  legacy/pilot proving artifacts, Circom and built policy CLI acceptance enabled:
  1734 passed, with one checkpoint test skipped, in 366.31 seconds. The same
  checkpoint passed separately on an owned local EVM (1 passed).
- The ordinary suite conditionally omits real authorization-mirror EVM behavior
  without reporting it as a pytest skip. Ran the existing `test_pilot_mirror.py`
  runner with `PYTEST_ADDOPTS` selecting
  `durable_current_inspection_real_pairing_and_revocation[authorization]` and
  coverage enabled. It passed (1 passed, 80 deselected, 137 seconds), exercising
  the real-chain branch as well as real PostgreSQL and proof verification.
  Deselected tests already ran in the complete suite; this focused run adds the
  otherwise conditional EVM environment. The runner's artifact doctor also
  confirmed development use and rejection of unapproved production use.
- Combined the three fresh coverage data files explicitly, retaining originals.
  Python coverage is 8002/8343 lines (95.91%) and 1850/2076 branches (89.11%).
  The previous complete report measured 7850/8343 lines and 1733/2076 branches;
  this refresh adds 152 lines and 117 branches. Remaining: 341 lines, 226 branches.
  Generated protobuf sources remain included: 70/152 lines and 3/8 branches;
  authored sources separately measure 7932/8191 lines (96.84%) and 1847/2068
  branches (89.31%). One preexisting coverage-excluded line remains in the report.
- Evidence under the external test cache: `full-coverage-python-eighth.log`,
  `full-coverage-checkpoint-eighth.log`, `full-coverage-mirror-eighth.log`, their
  matching `.data` files, and `full-coverage-combined-eighth.data`/`.json`.
  Ruff passes across tests; `uvx --offline reuse lint` passes for 709/709 files.
  Owned PostgreSQL and EVM services stopped after verification.
- Next Python priorities are pilot storage validation, chain reader/checkpoint
  failures, history timing, authorization mirroring, event ingestion and policy
  review. SDK branch, Solidity, docs/browser, operational-script coverage and
  final remote CI/merge verification remain unfinished. These local results do
  not establish full coverage or a published release.

## Forty-third checkpoint

- Added 41 PostgreSQL storage cases for noncanonical identifiers/nullifiers,
  unsupported operations/kinds, safe-integer revisions, scan limits, source
  sequences, non-object idempotent results and event scope capacity.
- Invalid idempotent callback results roll back records and consumption and allow
  the same request key to succeed on retry. Invalid revisions preserve existing
  encrypted records; invalid event sequences roll back inserted events. Exactly
  256 retained events are returned; 257 explicitly reject without truncation, and
  a foreign tenant still sees no events.
- All 63 storage tests pass; seven artifact-dependent tests are skipped in this
  focused invocation and were exercised in the forty-second checkpoint's full
  artifact-enabled suite. `src/storage/pilot.py` measures 183/183 statements and
  42/42 branches (`pilot-storage-boundaries.log`/`.data`). Ruff and whitespace
  pass; no production changes were required. The full goal remains incomplete.

## Forty-fourth checkpoint

- Added 28 chain-reader cases for invalid cache capacity, identifiers shortened
  by hexadecimal whitespace decoding, malformed roots/records, missing deployment
  configuration, invalid DIDs and RPC cancellation/retry.
- An event-loop ordering test exercises a slow completed request being replaced
  before its completion callback executes. The old callback preserves the new
  in-flight request and the replacement result populates the cache. Malformed
  replies are neither cached nor reported as absent records.
- All 47 reader tests pass, including the existing actual Web3 ABI encoding and
  decoding test with a controlled provider. Reader coverage is 153/153 statements
  and 42/42 branches (`chain-reader-complete.log`/`.data`). No public RPC was
  contacted, and no production changes were required. Ruff and whitespace pass.
- Full repository coverage remains unfinished. The forty-second checkpoint is
  still the last complete Python report; subsequent focused results must not be
  presented as a newly measured repository-wide percentage.

## Forty-fifth checkpoint

- Added 44 checkpoint tests using real Ed25519 root signatures and Web3's actual
  ABI decoding through a controlled provider. Cases cover tenant/publication
  identifiers, preceding revisions, deployment/observation configuration, signed
  context and RPC chain mismatches, empty/unapproved runtime code, stale/future
  blocks, each head field, publication-time bounds and a changed confirmation hash.
- Positive checks establish exact maximum block-age acceptance and that bytecode
  and head reads both use the initially observed block number before its hash is
  reconfirmed. No public RPC is contacted by the controlled provider.
- All 44 tests pass; `src/chain/pilot_checkpoint.py` measures 63/63 statements and
  24/24 branches (`checkpoint-boundaries.log`/`.data`). The existing real local-EVM
  integration separately passes through `scripts/test_checkpoint_evm.py`
  (`checkpoint-boundaries-evm.log`, 1 passed); its owned node is cleaned up.
- Ruff and whitespace checks pass. No production code, contracts or artifacts
  changed. Other Python paths, SDK/Solidity/docs/scripts and final remote checks
  remain unfinished; the full coverage objective remains active.

## Forty-sixth checkpoint

- Added 38 timestamp cases for authority interval/accuracy/delay/compromise bounds,
  root inventory limits, response size/type, safe review clocks, exclusive critical
  TSA certificate usage, timezone/precision conversion and decoded profile/accuracy
  guards. Invalid certificate tests use real signed X.509 certificates.
- Extended the synthetic OpenSSL TSA fixture to optionally omit accuracy. A new
  real response verifies cryptographically, then the application rejects its
  missing accuracy because it cannot establish a bounded observation interval.
  Existing fixture calls retain their one-second accuracy setting.
- Controlled decoded-object tests separately exercise unsupported profile and
  malformed accuracy guards. They explicitly do not establish cryptographic
  validity; the existing and new OpenSSL tests provide real signature evidence.
- All 46 timestamp tests pass. `src/prover/history_timing.py` measures 77/77
  statements and 24/24 branches (`history-timing-boundaries.log`/`.data`). Ruff
  and whitespace checks pass. No production source changed. Full repository
  coverage and publication verification remain incomplete.

## Forty-seventh checkpoint

- Added 19 real PostgreSQL policy-review cases covering effective approval clocks,
  duplicate business transfers/case IDs, future observations, each retained-parent
  consistency field, conflicting reviewed-case records and stored comparison
  digest/tenant/schema bindings. Rejected approvals leave no partial policy
  history; invalid-clock retries can subsequently succeed with the same key.
- Initial new-fixture errors used lists for strict tuple fields and changed the
  candidate's scope before evaluation. Corrected these to reach the intended
  duplicate and retained-parent checks, preserving normal policy evaluation.
- All 21 selected tests pass, including existing encrypted history/restart and
  JWT-protected HTTP/built CLI regressions. Policy review measures 95/95 statements
  and 38/38 branches (`policy-review-boundaries.log`/`.data`). The 68 deselected
  storage cases are outside this focused run. Owned PostgreSQL was stopped.
- Ruff and whitespace checks pass. No production source changed. Other Python,
  TypeScript, Solidity, docs/scripts and final publication requirements remain
  unfinished, and the last complete Python report is still checkpoint 42.

## Forty-eighth checkpoint

- Added 14 event-ingestion cases covering authority coherence/inventory, provider
  evidence bounds and collisions, 256-event capacity with exact retry, and
  retained event identity/scope/tenant mismatch. Real encrypted PostgreSQL rows
  establish that rejected retention leaves no partial event or index entries.
- Two explicitly labeled storage fault injections exercise missing indexed event
  and empty indexed scope guards; PostgreSQL constraints ordinarily prevent the
  missing-row condition. They are not claims of a reproduced database defect.
- All 20 selected tests pass, including HTTP, process-death rollback, Fireblocks
  and ageing-queue regressions. Event ingestion measures 110/110 statements and
  34/34 branches (`event-ingestion-boundaries.log`/`.data`). The 83 deselected
  storage tests are outside this focused run. Owned PostgreSQL was stopped.

## Forty-ninth checkpoint

- Added 23 Fireblocks adapter cases for canonical base64url, key snapshot/age
  configuration, JWKS inventory, real undersized RSA keys and detached-signature
  structure. Existing tests retain real locally signed notification coverage;
  no Fireblocks account, provider keys or live network is used.
- All 36 adapter tests pass, measuring 79/79 statements and 28/28 branches
  (`fireblocks-adapter-complete.log`/`.data`). Ruff and whitespace checks pass for
  both checkpoints. No production source changed.
- Full repository coverage remains incomplete across other Python paths, SDK,
  Solidity, docs/scripts and final remote publication checks. Checkpoint 42 is
  still the latest full Python measurement; these are focused module results.

## Fiftieth checkpoint

- Added 11 PostgreSQL wallet-service cases for invalid clocks, expiry after actual
  signature verification, signed evidence whose credential differs from current
  enrollment, attestation storage-key mismatch, revocation before issuance and
  conflicting retained extension fields. Real wallet signatures and encrypted
  records are used throughout; no cryptographic verification is mocked.
- Rejections preserve challenge/attestation/extension state as appropriate. An
  expiry rollback test uses explicit synthetic times to establish that no nonce
  consumption marker was written. Current status never reports mismatched
  enrollment evidence as verified.
- All 19 wallet integration tests pass, including existing HTTP, reconnect,
  concurrency, quota, migration, expiry and revocation checks. Wallet service
  coverage is 120/120 statements and 34/34 branches
  (`wallet-service-boundaries.log`/`.data`). Ruff and whitespace checks pass;
  owned PostgreSQL was stopped. No production changes were required.
- The repository-wide coverage goal remains incomplete. Other Python modules,
  SDK branches, Solidity, docs/scripts and final remote CI/merge evidence remain
  outstanding. Checkpoint 42 remains the last complete Python measurement.

## Fifty-first checkpoint

- Extended the artifact-enabled authorization integration scenario with 12
  dependency-boundary rejection checks: zero consumer, missing/wrong-schema proof,
  six invalid or non-ALLOW inspection results, two missing source records and an
  expired valuation checkpoint interval. A real successful evaluation establishes
  the baseline before controlled dependency-result changes; patches are restored
  and the original evidence still prepares successfully afterward.
- The real PostgreSQL/development-proof scenario passes (1 passed, 102 deselected,
  129.26 seconds). Authorization mirror coverage improves to 86/89 statements and
  23/26 branches (`authorization-mirror-boundaries.log`/`.data`). Three paths remain:
  information binding, envelope binding and missing participant evidence. These
  require inputs that reach the guards through the earlier integrity checks.
- The existing scenario verifies record and consumption counts are unchanged.
  This focused invocation does not enable the optional local-EVM publication
  branch; checkpoint 42 remains its latest execution evidence. Owned PostgreSQL
  stopped; Ruff and whitespace checks pass. No production source changed.
- Full repository coverage remains incomplete, including this module's remaining
  paths and other Python, SDK, Solidity, docs/scripts and publication requirements.

## Fifty-second checkpoint

- Added three authorization-mirror integrity cases that reconstruct proof/receipt
  digests, sign candidate receipts with the synthetic decision authority, encrypt
  retained records and update the isolated database's consumption reference.
  Real earlier digest/signature/storage checks therefore pass before rejection
  of mismatched information or recipient-envelope binding.
- The missing-participant case additionally injects an ALLOW evaluation result
  to exercise the mirror's independent final participant-evidence requirement.
  It is a dependency-contract check, not a claim that the configured real policy
  approves missing evidence. Digest, signature and storage checks remain real.
- Every altered record/reference is restored in a finally block, including the
  original encrypted proof bytes; the original authorization prepares afterward.
  The surrounding scenario checks unchanged record/consumption counts.
- The artifact-enabled PostgreSQL scenario passes (1 passed, 102 deselected,
  125.45 seconds). Authorization mirror now measures 89/89 statements and 26/26
  branches (`authorization-mirror-complete.log`/`.data`). Ruff and whitespace
  pass; owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete; the latest full Python report is
  checkpoint 42, and remaining Python, SDK, Solidity, docs/scripts and remote
  publication requirements still need completion and verification.

## Fifty-third checkpoint

- Added three docs unit tests for the authored root-layout composition, page-map
  failure propagation and MDX component override delegation. Nextra dependencies
  are controlled; these tests do not establish browser hydration or MDX rendering.
- All 50 docs tests pass with 26/26 lines/statements, 6/6 functions and 6/6 branches
  across authored TS/TSX. Added 100% gates for those measured metrics and documented
  the scope in `apps/docs/README.md`. Existing CI already runs this coverage command.
- Evidence: `docs-layout-gate.log`, `docs-layout-coverage.log`, and
  `docs-layout-typecheck.log`. TypeScript checking passes from the docs workspace;
  whitespace checks pass. No product code changed.
- MDX page/browser coverage, operational scripts and the other outstanding
  repository requirements remain necessary. Full coverage is not established by
  this source-unit gate. A fresh full Python regression is running separately.


## Fifty-fourth checkpoint

- Refreshed the complete Python suite with PostgreSQL, development legacy/pilot
  artifacts, Circom and built policy CLI acceptance enabled: 1952 passed, one
  checkpoint skipped, in 422.26 seconds. That checkpoint passed separately on its
  owned local EVM (1 passed). The optional authorization-mirror EVM path also
  passed with the new shared integrity checks (1 passed, 154 deselected, 153.07
  seconds). These deselections narrow the additional EVM run; the complete suite
  already exercised the ordinary paths.
- Explicitly combined all three fresh coverage files, retaining originals.
  Python measures 8076/8343 lines (96.80%) and 1926/2076 branches (92.77%). This
  adds 74 lines and 76 branches over checkpoint 42. Remaining: 267 lines and 150
  branches. Generated protobuf sources remain included (70/152 lines, 3/8 branches);
  authored sources separately measure 8006/8191 lines (97.74%) and 1923/2068
  branches (92.99%). One preexisting excluded line remains in the report.
- Evidence under the external test cache: `full-coverage-python-ninth.log`,
  `full-coverage-checkpoint-ninth.log`, `full-coverage-mirror-ninth.log`, matching
  `.data` files, and `full-coverage-combined-ninth.data`/`.json`. Ruff passes across
  tests, REUSE passes for 711/711 tracked files, and owned PostgreSQL/EVM services
  stopped. Docs' 50-test source gate and typecheck also passed this checkpoint.
- Next Python priorities are publication journal, proof routes, authorization
  evidence, policy activation, proof observations and registrar/timestamp-evidence
  boundaries. SDK branches, Solidity, MDX/browser, scripts and final remote CI,
  merge and merged-main verification remain unfinished. Full coverage is not yet
  established; no local percentage is a released coverage claim.

## Fifty-fifth checkpoint

- Added 16 publication-journal cases for nonzero registry/sender, unavailable or
  expired consumed authority, canonical intent IDs, altered authenticated retained
  content, index/encrypted-binding mismatches and unavailable intent handling.
- A real PostgreSQL race synchronizes both broadcast callers after their initial
  reads and revalidation. The locked second check permits one claim and exactly
  one controlled send; the losing caller receives a conflict. Signed transaction
  bytes are real, but no transaction is sent to a network.
- All 43 journal tests pass, including existing restart, uncertainty/recovery and
  retained-history checks. Publication journal measures 118/118 statements and
  32/32 branches (`publication-journal-complete.log`/`.data`). Ruff and whitespace
  pass; owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete. Checkpoint 54 is the latest full
  Python report; other Python, SDK, Solidity, MDX/browser, scripts and final
  remote CI/merge requirements remain outstanding.

## Fifty-sixth checkpoint

- Added 15 PostgreSQL policy-activation cases for invalid clocks, malformed
  encrypted head/predecessor fields, redundant/backdated selection, scope-key
  mismatch and proof evaluation outside the selected policy's activation interval.
- Rejections preserve the retained activation revision/value. Invalid-clock
  requests leave no selection and permit a valid retry with the same key. Exact
  activation-time evaluation remains accepted.
- All 16 selected tests pass, including existing concurrent selection, restart
  and explicit reviewed rollback history. Policy activation measures 65/65
  statements and 22/22 branches (`policy-activation-complete.log`/`.data`). The
  other 102 storage tests were deselected for this focused run. Ruff/whitespace
  pass; owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete. Checkpoint 54 is the latest full
  Python report, with other Python, SDK, Solidity, MDX/browser, operational scripts
  and remote CI/merge requirements still outstanding.

## Fifty-seventh checkpoint

- Added 15 PostgreSQL authorization-evidence capture cases for every missing
  selected record, local revocation, empty/oversized configuration rollback,
  chunk boundaries/reuse, authenticated chunk conflict and retained revision pins.
- The capture fixture uses explicitly synthetic minimal prevalidated-input
  records. It tests persistence and reference capture, not cryptographic or
  enrollment authenticity. Missing-record cases fault-inject the read boundary;
  storage, encryption, chunk hashes and transaction rollback remain real.
- Exact 32 KiB/128 KiB boundaries reconstruct the original bytes; a second capture
  reuses chunks. After a source update, the original manifest still references
  the original revision and its hash, never the changed head.
- All 15 selected tests pass; authorization evidence measures 40/40 statements
  and 18/18 branches (`authorization-evidence-complete.log`/`.data`). The other
  118 storage tests were deselected. Ruff/whitespace pass; owned PostgreSQL
  stopped. No production source changed.
- Full repository coverage remains incomplete; checkpoint 54 is the last full
  Python measurement. Other Python paths, SDK, Solidity, MDX/browser, scripts
  and final remote CI/merge verification remain outstanding.

## Fifty-eighth checkpoint

- Added ten observation-model cases for sorted/unique fact references, pairing
  versus policy presence, policy/transfer/clock binding and unsupported versions.
  Added seven service validation cases inside the real authorization/observation
  scenario for invalid clocks and malformed fact inventories.
- The integration checks unchanged retained-record counts after validation errors,
  then successfully reuses the same idempotency key. Existing real proof,
  PostgreSQL, HTTP/CLI, non-consumption, concurrency and rollback behavior passes.
- All 14 selected tests pass in 142.81 seconds. Proof observation measures 96/96
  statements and 18/18 branches (`proof-observation-complete.log`/`.data`). Ruff
  and whitespace pass; owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete. Checkpoint 54 is the latest full
  Python measurement; other Python paths, SDK, Solidity, MDX/browser, operational
  scripts and final remote CI/merge verification remain outstanding.

## Fifty-ninth checkpoint

- Added 15 registrar cases for issuer inventories, revision and lifetime bounds,
  retained source reuse and conflicting-source rollback using real PostgreSQL
  and encrypted storage. A conflict leaves both root collections empty and the
  original source unchanged; exact source reuse and idempotent retry succeed.
- All 16 selected tests pass in 12.88 seconds; registrar measures 69/69
  statements and 20/20 branches (`registrar-complete.log`/`.data`).
  The other 132 storage tests were deselected. Ruff/whitespace pass; owned
  PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete; checkpoint 54 remains the last
  full Python report. Other Python paths, SDK, Solidity, MDX/browser, scripts
  and remote CI/merge verification remain outstanding.

## Sixtieth checkpoint

- Added 21 timestamp record parsing tests: exact byte round trips across chunk
  boundaries and the 32 KiB maximum; wrong schema/tenant/receipt; malformed
  record/response types, chunk lengths/counts and Base64; and decoded overflow
  that still fits the encoded chunk-count limit.
- All 21 pass in 4.60 seconds (`timestamp-framing.log`/`.data`). These
  exercise framing only, not timestamp signature authenticity. The focused
  service-module report is 19/47 statements with attachment paths unexecuted;
  no claim of whole-module completion is made. Existing real signed timestamp
  integration evidence remains in checkpoint 54's broader run.
- Registrar work is committed as 7d018a1. No production source changed.
  Full repository coverage and final remote CI/merge verification remain
  incomplete; timestamp attachment rejection/conflict cases remain next work.

## Sixty-first checkpoint

- Extended the real authorization scenario with five invalid timestamp-response
  type/size checks and four missing or mismatched receipt/proof checks. The
  latter fault-inject storage reads; record counts remain unchanged. Successful
  attachment still uses real decision signatures, TSA verification and encrypted
  PostgreSQL storage.
- A second authentic TSA response with a distinct serial is rejected as a
  retained-evidence conflict. The original response survives database reconnect
  and the remainder of the real proof, export/history and CLI scenario passes.
- Combined with the 21 parsing cases, all 22 selected tests pass in 136.16
  seconds. Timestamp evidence measures 47/47 statements and 14/14 branches
  (`timestamp-evidence-complete.log`/`.data`). Ruff/format/whitespace pass;
  owned PostgreSQL stopped. No production source changed.

## Sixty-second checkpoint

- Added eight publication reconciliation cases for a zero registry, invalid
  clocks, missing retained intent, changed inclusion header and changed receipt
  during repeated observation. Early failures avoid unnecessary reads; changed
  observations cannot return a stable success report.
- All 33 unit tests pass in 3.71 seconds, measuring 120/120 statements and 48/48
  branches (`publication-reconciliation-complete.log`/`.data`). These use
  controlled RPC responses, not a live chain. Existing EVM evidence is recorded
  in checkpoint 54; it was not rerun for these unit-only additions.
- Ruff/format/whitespace pass. No production source changed. Full repository
  coverage remains incomplete; checkpoint 54 remains the latest full Python
  report. Other Python paths, SDK, Solidity, MDX/browser, scripts and final
  remote CI/merge verification remain outstanding.

## Sixty-third checkpoint

- Added 22 inner historical reconstruction rejection checks inside the real
  authorization scenario: independent trust, authorization-time boundaries,
  missing/duplicate enrollment, enrollment schema/commitment/acceptance times,
  captured credential status, fact inventories, retained schema and fact identity.
- These directly test inner reconstruction against copies of the authentic
  bundle, independently of the outer integrity hash. The unchanged bundle
  still reproduces policy and passes the existing complete history inspection
  with real signatures, pairing, PostgreSQL and CLI behavior.
- The selected integration test passes in 116.96 seconds. History policy measures
  34/34 statements and 12/12 branches; history statement measures 50/50 statements
  and 14/14 branches (`history-reconstruction-complete.log`/`.data`).
  Ruff/format/whitespace pass; owned PostgreSQL stopped. No source changed.

## Sixty-fourth checkpoint

- Added 12 event reconciliation tests for nonzero EVM deployment bounds, block
  identity requirements, projection clock types/ranges and source sequence order
  disagreeing with event time. The higher sequence remains the stream head
  regardless of input order, while the timeline remains chronologically sorted.
- All 32 tests pass in 0.43 seconds; event reconciliation measures 135/135
  statements and 58/58 branches (`event-reconciliation-complete.log`/`.data`).
  Ruff/format/whitespace pass. No production source changed.
- Full repository coverage remains incomplete; checkpoint 54 is the latest full
  Python report. Other Python paths, SDK, Solidity, MDX/browser, scripts and
  final remote CI/merge verification remain outstanding.

## Sixty-fifth checkpoint

- Added 22 encrypted authorization-input tests covering outer row revision/type/
  size, exact decoded schema, chunk framing, noncanonical Base64 padding bits,
  decoded overflow and round trips at one byte, chunk edges and 32 KiB.
- Tests use real record encryption and explicitly unverified synthetic approval
  objects: successful sealing/opening does not authenticate an approval. A chunk
  larger than 4096 characters is rejected by canonical serialization before
  ciphertext creation; that test asserts the actual boundary separately.
- All 24 tests pass in 0.57 seconds; authorization input measures 42/42 statements
  and 14/14 branches (`authorization-input-complete.log`/`.data`).
  Ruff/format/whitespace pass. No production source changed.
- Full repository coverage remains incomplete; checkpoint 54 remains the last
  full Python measurement. Other Python paths, SDK, Solidity, MDX/browser,
  operational scripts and remote CI/merge verification remain outstanding.

## Sixty-sixth checkpoint

- Added eight local exchange checks inside the real authorization scenario:
  unsupported behavior, tenant mismatch, four invalid delivery clocks and
  unavailable receipt/proof records. Missing records fault-inject the read
  boundary; encrypted storage and idempotency remain real.
- Rejected requests leave record counts unchanged. The same delivery identity
  then succeeds concurrently and replays after reconnect. Existing recipient-key
  retirement, evidence retention and event reconciliation checks also pass.
- The selected integration test passes in 134.45 seconds, with local exchange
  measuring 44/44 statements and 10/10 branches
  (`local-exchange-complete.log`/`.data`). Ruff/format/whitespace pass;
  owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete; checkpoint 54 is the latest full
  Python report. Bilateral receiver guards, other Python paths, SDK, Solidity,
  MDX/browser, scripts and final remote CI/merge verification remain outstanding.

## Sixty-seventh checkpoint

- Added bilateral receiver checks for a valid self-hosted beneficiary (unsupported
  by this simulator), invalid behavior/clock configuration, extra/missing message
  fields, timeout deadline types and exact lifetime boundaries, and a substituted
  information signature. The signature case checks both its specific internal
  rejection and the public redacted error.
- Original authentic requests still pass every supported behavior, key overlap,
  CLI and durable local exchange scenario. A fixture spelling error was corrected
  before the accepted run; no production source changed.
- The selected real authorization integration test passes in 113.93 seconds.
  Bilateral receiver measures 62/62 statements and 20/20 branches
  (`bilateral-complete.log`/`.data`). Ruff/format/whitespace pass;
  owned PostgreSQL stopped.
- Full repository coverage remains incomplete; checkpoint 54 is the last full
  Python measurement. Proof-route gaps, other Python paths, SDK, Solidity,
  MDX/browser, operational scripts and remote CI/merge verification remain.

## Sixty-eighth checkpoint

- Added six proof-route cases for invalid envelope configuration before discovery,
  absent/successful discovery keys, missing verification-key artifacts,
  jurisdiction scalar overflow and an unbuilt sanctions tree before proving.
  Extended the legacy HTTP generation case to verify empty and explicit domain
  configuration at the prover's decimal-string input boundary.
- All 49 selected API/route tests pass in 4.15 seconds
  (`proof-route-boundaries.log`/`.data`). This narrow report covers 228/256
  statements and leaves six partial branches; durable database and real-artifact
  paths covered by broader suites were not run here. No full module coverage
  claim is made. Ruff/format/whitespace pass; no production source changed.
- The unused transfer-hash helper remains unexecuted in the last full report.
  A refreshed complete Python run is needed to consolidate checkpoints 55–68
  before selecting the remaining gaps. Full repository coverage, other source
  workspaces, operational coverage and remote CI/merge verification remain open.


## Sixty-ninth checkpoint

- Refreshed the complete Python run with real PostgreSQL, both development
  artifact profiles and CLI acceptance enabled: 2093 passed, one checkpoint
  skip, 40 warnings, 446.58 seconds (`full-coverage-python-tenth.log`).
- The separately owned local-EVM checkpoint passes (one test, 2.09 seconds).
  The authorization mirror EVM scenario passes (one selected test, 213
  deselected, 147.37 seconds). Both runners exited successfully after cleanup.
- Explicitly combined only these three coverage data files. All Python measures
  8154/8343 lines (97.73%) and 2004/2076 branches (96.53%), leaving 189 lines
  and 72 branches. Generated protobuf modules remain included: 70/152 lines
  and 3/8 branches. Authored source separately measures 8084/8191 lines
  (98.69%) and 2001/2068 branches (96.76%). One preexisting default coverage
  exclusion remains; it has not been expanded to hide uncovered code.
- This replaces checkpoint 54's baseline and records 78 additional covered lines
  and 78 additional covered branches. Reports are
  `full-coverage-{python,checkpoint,mirror,combined}-tenth.data`, with full
  and combined JSON inventories. Ruff across tests and REUSE (712/712 files)
  pass. Owned PostgreSQL stopped; no generated artifacts or source files changed.
- Largest authored line gaps now include API authentication/configuration paths.
  Four-branch gaps remain in publication recovery, proof preparation, pilot
  projection and historical verification/status. The unused proof-route hash
  helper still has two unexecuted lines.
- Full objective remains incomplete: remaining Python gaps, SDK residual
  statements/branches, Solidity coverage, MDX/browser, operational scripts and
  final remote CI/merge verification must still be resolved.

## Seventieth checkpoint

- Added 16 authentication middleware cases: real ES256 valid/expired/wrong-key
  tokens, missing JWT dependency/public key, unknown authentication mode,
  missing/mismatched/unconfigured API keys, valid minimal claims and actual
  missing/wrong-scheme bearer parsing in JWT and SIWE modes.
- JWT dependency absence is isolated through the import cache and restored by
  pytest; cryptographic verification uses fresh synthetic EC keys. Existing
  real SIWE route scenarios run alongside these tests.
- All 18 selected tests pass in 4.99 seconds. Authentication middleware measures
  60/60 statements and 20/20 branches (`auth-middleware-complete.log`/`.data`).
  Ruff/format/whitespace and REUSE (713/713 files) pass. No production source
  changed.
- Full repository coverage remains incomplete. Checkpoint 69 is the latest
  complete Python baseline; route configuration, remaining Python service and
  verifier guards, generated code, other workspaces and final remote CI/merge
  verification remain outstanding.

## Seventy-first checkpoint

- Added 26 route dependency/error-mapping cases: absent/None/unready databases
  across wallet, enrollment, policy and event services; missing/invalid encryption
  keys; invalid deployment chain values for the two services that read them;
  wallet quota/integrity failures; and enrollment revocation eligibility/conflict.
- These isolate synchronous route dependency configuration and async handler
  error mapping without database I/O. They are not HTTP transport or durable
  lifecycle tests; existing real integration evidence remains checkpoint 69.
- All 26 pass in 5.67 seconds (`pilot-route-configuration.log`/`.data`).
  The narrow four-module report covers 150/251 statements and is not a full
  route coverage claim. Ruff/format/whitespace and REUSE (714/714 files) pass.
  No production source changed.
- Full objective remains incomplete. Fireblocks/policy error mapping, remaining
  Python service/verifier and generated-code paths, other workspaces, operational
  checks and final remote CI/merge verification remain outstanding.

## Seventy-second checkpoint

- Extended the real Fireblocks relay scenario with intake conflict/type/value/
  recursion failures, duplicate integration IDs and an empty verification-key
  inventory. Intake exceptions are injected; existing JWT, provider signatures,
  PostgreSQL retention and retries remain real. Configuration validation uses
  actual malformed configuration, not a mocked constructor.
- Failed requests preserve the original retained notification: subsequent exact
  replay is still a duplicate and retained record counts stay unchanged.
- Both selected Fireblocks integration tests pass in 7.93 seconds (146 others
  deselected), measuring 62/62 statements and 6/6 branches in the HTTP route
  (`fireblocks-route-complete.log`/`.data`).

## Seventy-third checkpoint

- Added a real PostgreSQL policy-approval idempotency conflict with a different
  valid review, followed by successful replay of the original review and
  successful approval under a fresh key. Added two real-JWT HTTP cases mapping
  injected comparison errors to a redacted 422 response.
- Together with existing policy and route-configuration tests, all 44 selected
  cases pass in 20.56 seconds. Policy route measures 68/68 statements and 6/6
  branches (`policy-route-complete.log`/`.data`).
- Ruff/format/whitespace pass; owned PostgreSQL stopped. No production source
  changed. Full repository coverage remains incomplete; checkpoint 69 is the
  latest complete Python baseline, with remaining service/verifier/generated
  paths, other workspaces, operational checks and remote CI/merge still open.

## Seventy-fourth checkpoint

- Added nine publication recovery scenarios for noninteger/out-of-range attempt
  counters, stale attempt state, missing intent, policy changes during source
  revalidation, stale head and future head.
- Existing real PostgreSQL journal reservation/claim handling remains in use.
  RPC, source validation and sending are controlled test boundaries; no public
  transaction is broadcast. Every failed recovery leaves the attempt count at
  one and never invokes the sender.
- All 43 journal integration tests pass in 19.20 seconds. Publication recovery
  measures 60/60 statements and 22/22 branches
  (`publication-recovery-complete.log`/`.data`). Ruff/format/whitespace pass;
  owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete. Checkpoint 69 is the latest full
  Python baseline; other service/verifier guards, generated modules, other
  workspaces, operational checks and final remote CI/merge remain outstanding.

## Seventy-fifth checkpoint

- Added 13 historical-status tests using real Ed25519 signed synthetic receipts:
  valid historical verification after key expiry, empty/duplicate/oversized
  authority inventories, canonical issuer requirements, missing/duplicate
  credential records, credential scope substitutions, compromise policy,
  altered manifest and absent registry delegation.
- This fixture supplies prevalidated enrollment structure without claiming an
  enrollment signature or proof was reconstructed here. The status verifier's
  real signature and independent delegation checks execute; complete outer
  reconstruction remains covered by checkpoint 69's integration evidence.
- All 13 pass in 2.30 seconds; historical status measures 42/42 statements and
  12/12 branches (`history-status-complete.log`/`.data`). The canonical-name
  case uses a bare DNS name accepted by discovery but rejected as an issuer DID.
  Ruff/format/whitespace and REUSE (715/715 files) pass; no source changed.
- Full coverage remains incomplete: remaining Python service/verifier/generated
  paths, other workspaces, operational tests and remote CI/merge verification
  remain open. Checkpoint 69 is still the latest complete Python measurement.

## Seventy-sixth checkpoint

- Added five proof-preparation consistency cases inside the durable registrar
  round trip: source scope, issuance issuer, missing issuer entry, wrong issuance
  snapshot binding and disagreement with expected current public signals.
- Source cases explicitly isolate checks after credential trust validation.
  They recompute actual source digests but use altered unsigned snapshot copies
  and a controlled current-credential result; they do not claim authentic
  registrar approvals. The original signature/root paths remain real in the
  surrounding integration scenario. Final-statement fault injection changes
  one result only after the normal statement calculation succeeds.
- The unchanged inputs still return the original witness, generate a real proof,
  pass current inspection and reject subsequent revocation. The selected test
  passes in 13.62 seconds. Proof preparation measures 45/45 statements and 18/18
  branches (`proof-preparation-complete.log`/`.data`).
- Ruff/format/whitespace pass; owned PostgreSQL stopped. No source changed.
  Full coverage remains incomplete; checkpoint 69 is the latest full baseline,
  with other Python, generated-code, workspace, operational and remote CI/merge
  requirements still outstanding.

## Seventy-seventh checkpoint

- Added 22 projection validation tests for exact digest width and limb ordering,
  immutable 48-field inventory, remainder types/canonical integer/range bounds,
  invalid digest-limb types/ranges and normal frozen-object mutation rejection.
- All 44 projection tests pass in 13.87 seconds, including existing real Circom
  substitution tests. Projection measures 51/52 statements and 13/14 branches
  (`projection-boundaries.log`/`.data`).
- Line 107's defensive commitment-length rejection remains uncovered. Normal
  construction already rejects a non-48-field tuple and the instance is frozen;
  no forced mutation or bypassed constructor was introduced solely to hit it.
  It remains in the denominator for explicit final review, not silently excluded.
- Ruff/format/whitespace pass. No production source changed. Full repository
  coverage remains incomplete; checkpoint 69 is the latest complete Python
  baseline. Other Python/generated paths, workspaces, operational coverage and
  final remote CI/merge verification remain outstanding.

## Seventy-eighth checkpoint

- Added 21 malformed jurisdiction/threshold signal tests using the shared legacy
  proof fixture: incomplete inventories, invalid numeric values, out-of-range
  or non-uppercase ASCII encodings, malformed submitted thresholds, and
  case-insensitive comparison against the expected jurisdiction.
- Combined with existing threshold and jurisdiction integration cases, all 55
  selected tests pass in 5.97 seconds. Tier mapping measures 45/45 statements
  and 18/18 branches (`tier-mapping-boundaries.log`/`.data`).
- These verify configured software behavior, not the legal adequacy of the
  configured thresholds. No threshold values or production code changed.
  Ruff/format/whitespace and REUSE (716/716 files) pass.
- Full repository coverage remains incomplete. Checkpoint 69 is the latest full
  Python report; remaining Python/generated branches, other workspaces,
  operational checks and final remote CI/merge verification remain open.

## Seventy-ninth checkpoint

- Added six enrollment checks to the durable lifecycle scenario: missing
  enrollment, substituted retained tenant/credential/commitment, revocation
  before acceptance and cross-tenant retained revocation input.
- Substituted rows fault-inject read results; no forged records are persisted.
  The missing-enrollment and early-revocation checks use actual PostgreSQL.
  The original credential remains unchanged and no revocation exists after
  rejection; the normal revoke/retry/reconnect and signature checks still pass.
- The selected integration test passes in 6.07 seconds; enrollment service
  measures 69/69 statements and 18/18 branches
  (`enrollment-service-complete.log`/`.data`). Ruff/format/whitespace pass;
  owned PostgreSQL stopped. No production source changed.
- Full repository coverage remains incomplete. Checkpoint 69 is the latest full
  Python report. Remaining service/verifier/generated paths, other workspaces,
  operational checks and final remote CI/merge verification remain outstanding.

## Eightieth checkpoint

- Added nine valuation/private-tier tests for absent/list/wrong-length threshold
  inventories and zero, negative, noncanonical or oversized amount strings.
  Existing Python-plus-circuit unordered-threshold tests are retained without
  duplicating them.
- All 39 valuation tests pass in 5.02 seconds, including real full-width circuit
  arithmetic, forged-tier and modular-alias rejection. Pilot valuation measures
  15/16 statements and 5/6 branches (`pilot-valuation-boundaries.log`/`.data`).
- Line 11's repeated quotient-consistency rejection remains unexecuted because
  Transfer model validation enforces the same invariant first. It stays visible
  for final review; no validator bypass or coverage exclusion was added.
- Ruff/format/whitespace pass. No source changed. Full repository coverage
  remains incomplete; checkpoint 69 is the latest complete Python baseline.
  Other Python/generated paths, workspace coverage, operational tests and
  final remote CI/merge verification remain outstanding.

## Eighty-first checkpoint

- Added four database lifecycle tests for missing/empty connection configuration
  without pool allocation and disconnected connection/transaction entry before
  and after idempotent close.
- New tests plus real PostgreSQL proof-storage tests pass 36 cases in 8.77
  seconds. Four proof-persistence tests additionally pass in 6.10 seconds,
  covering successful shared transactions, atomic audit failure rollback,
  concurrent retries and duplicate-nullifier rollback.
- Coverage from the four persistence tests is explicitly appended to the
  lifecycle/storage data file. Database measures 79/79 statements and 16/16
  branches (`database-complete.data`, `database-complete.log`,
  `database-transactions.log`).
- Ruff/format/whitespace and REUSE (717/717 files) pass; owned PostgreSQL
  stopped. No production source changed. Full coverage remains incomplete:
  remaining Python/generated paths, other workspace and operational coverage,
  and final remote CI/merge verification are still outstanding.

## Eighty-second checkpoint

- Added five proof-inspection boundary checks inside the registrar round trip:
  None/dictionary server configuration and each unavailable issuance/issuer/
  sanctions root. Root absence is injected at the transaction read boundary;
  the original stored roots remain unchanged.
- The subsequent unmodified preparation and real proof inspection still pass.
  The selected integration test passes in 15.01 seconds
  (`proof-inspection-boundaries.log`/`.data`). Its focused report covers
  68/81 statements; policy evaluation and active-policy mismatch paths belong
  to the broader suite and were not exercised in this invocation.
- The additions hit both previously missing branches in checkpoint 69's full
  inspection report, but no refreshed full-module claim is made from this narrow
  run. Ruff/format/whitespace pass; owned PostgreSQL stopped. No source changed.
- Full repository coverage remains incomplete. Other Python/generated paths,
  workspace and operational coverage, plus final remote CI/merge verification
  remain outstanding.

## Eighty-third checkpoint

- Added two real signed-root/PostgreSQL checks: revision two cannot initialize
  an empty root history, and the shared persistence helper rejects a valid
  tenant-a approval inside a tenant-b transaction.
- Both rejected paths leave no root record. The initial revision then succeeds
  with the same idempotency key; existing concurrent successor/fork, reconnect,
  predecessor and expiry checks still pass.
- The selected integration test passes in 8.52 seconds
  (`root-publication-boundaries.log`/`.data`). Its focused report covers
  39/41 statements and 12/14 branches; issuance-specific scope checks exercised
  elsewhere are not included in this narrow invocation. Both gaps identified
  by checkpoint 69 are now hit, without claiming a new full aggregate report.
- Ruff/format/whitespace pass; owned PostgreSQL stopped. No source changed.
  Full repository coverage remains incomplete, including remaining Python/
  generated paths, other workspaces, operational and remote CI/merge checks.

## Eighty-fourth checkpoint

- Added five fact-evidence checks: list/duplicate/oversized reference inventories
  and substituted signed record identity during both loading and retention.
  Substitution uses another actually signed fixture approval at the read boundary;
  original encrypted PostgreSQL records remain unchanged.
- Original loading succeeds after the injected failures. Existing concurrent
  retention, rollback, reconnect, expiry, tenant scope and wrong-key checks pass.
  The selected integration test passes in 9.32 seconds; fact evidence measures
  49/49 statements and 14/14 branches
  (`fact-evidence-complete.log`/`.data`).
- Ruff/format/whitespace pass; owned PostgreSQL stopped. No production source
  changed. Full repository coverage remains incomplete; checkpoint 69 remains
  the latest full Python baseline. Remaining Python/generated paths, other
  workspaces, operational checks and final remote CI/merge remain outstanding.

## Eighty-fifth checkpoint

- Added 11 tree boundary tests: malformed entry identifiers and invalid/oversized
  sanctions inventory containers. Rejected sanctions input never reaches hashing.
  Existing dense-reference tests now also assert published entry order and depth.
- All 20 tree tests pass in 0.39 seconds; pilot tree measures 51/51 statements and
  20/20 branches (`pilot-tree-boundaries.log`/`.data`). The sanctions report
  is intentionally partial (18/36 statements); this invocation tests its input
  boundary, not normal sanctions witness generation.

## Eighty-sixth checkpoint

- Added a Poseidon constants test using an actual temporary numeric-JSON encoding
  of the committed constants, checked against all existing fixed reference
  vectors. It clears the cache, restores the original constants path and checks
  a reference vector again to prevent cross-test contamination.
- All 14 Poseidon tests pass in 9.64 seconds, including live parity and constants
  regeneration checks. Poseidon measures 48/48 statements and 12/12 branches
  (`poseidon-complete.log`/`.data`).
- Ruff/format/whitespace pass. No production constants or source changed.
  Full repository coverage remains incomplete. Checkpoint 69 is the latest full
  Python report; remaining Python/generated paths, other workspaces, operational
  tests and final remote CI/merge verification remain open.

## Eighty-seventh checkpoint

- Added three actual HTTP tests for authenticated empty metrics, independent
  generation/verification averages and rounding, and unauthenticated liveness
  with no database configured. Each fixture owns fresh counters and restores
  the module's original clock/store.
- All three pass in 3.88 seconds. Health/metrics measures 47/47 statements and
  4/4 branches (`health-metrics-complete.log`/`.data`). Tests preserve the
  documented distinction: health is process liveness, not dependency readiness;
  metrics are process-local counters, not durable pilot reports.
- Ruff/format/whitespace and REUSE (718/718 files) pass. No source changed.
  Full repository coverage remains incomplete. Checkpoint 69 is the latest
  full Python baseline; other Python/generated paths, workspace and operational
  coverage, and final remote CI/merge verification remain outstanding.

## Eighty-eighth checkpoint

- Credential status now treats the exact expiry second as expired, consistent
  with proof generation. The new HTTP boundary regression first reproduced the
  defect (one failure, four passes in `credential-status-before.log`). It covers
  before/equal/after expiry and revocation precedence without mutating records.
- After the source fix, all 53 API endpoint and proof-route failure tests pass
  in 6.44 seconds. Credential routes measure 71/71 statements and 10/10 branches
  (`credential-status-complete.log`/`.data`). Ruff and whitespace checks pass.
- Full repository coverage remains incomplete. Checkpoint 69 is the latest full
  Python baseline and predates this source fix; a new full run is required.
  Remaining Python/generated, workspace and operational coverage and remote
  CI/merge verification remain outstanding.

## Eighty-ninth checkpoint

- Added authenticated authorization HTTP checks for unsupported operator assurance,
  missing enrollment and stored-evidence integrity failure. The assurance stand-in
  is explicitly not a validated artifact manifest; service failures are injected
  only at the route boundary, then restored before real consumption races.
- Responses retain bounded 503/404 details and redact the injected private marker.
  Existing database assertions verify rejected requests leave records and
  consumptions unchanged; subsequent actual proof/authorization/retry/history
  checks pass. The selected real-artifact PostgreSQL scenario passes in 150.63
  seconds, with authorization routes at 51/51 statements and 8/8 branches
  (`authorization-route-complete.log`/`.data`).

## Ninetieth checkpoint

- Added five public bridge export tests: each possible first lazy gRPC export,
  identity of every resolved class, subsequent cached access and unknown-name
  rejection. Monkeypatch restoration preserves the original module export state.
- All 22 gRPC bridge tests pass in 2.44 seconds. The package initializer measures
  13/13 statements and 4/4 branches; gRPC implementation measures 140/140 and
  18/18 (`bridge-exports-complete.log`/`.data`). The broader bridge report remains
  partial because this invocation does not exercise other protocols/generated
  paths; it is not a new aggregate baseline.
- Ruff, format and whitespace checks pass. No production source changed in these
  two checkpoints. Owned PostgreSQL stopped after validation. Full repository
  coverage remains incomplete; the next full Python run, remaining workspace and
  operational coverage, and remote CI/merge verification are still required.

## Ninety-first checkpoint

- Extended the real authorization/history scenario with invalid authorization
  clocks, payload type/size boundaries and duplicate/oversized fact inventories.
  Existing database invariants confirm failures do not retain records or consume
  authorization before the subsequent real successful operation.
- History tests reject invalid reviewer clocks and independently remove each
  captured configuration item. Explicit boundary doubles exercise reconstructed
  signal mismatch (pairing must not run) and negative pairing (no policy outcome
  claimed), alongside the existing actual reconstruction and pairing checks.
- The real-artifact PostgreSQL scenario passes in 126.90 seconds. History measures
  186/186 statements and 34/34 branches; proof authorization measures 51/51 and
  12/12 (`history-outcomes-complete.log`/`.data`).

## Ninety-second checkpoint

- Added a legacy signal decoder regression for JSON integer-conversion failure,
  with a pinned/restored interpreter digit limit and input below the storage byte
  bound. The public error remains bounded and omits parser implementation details.
- All 44 decoder/model tests pass in 1.68 seconds. All 32 actual PostgreSQL proof
  storage/migration tests pass in 10.91 seconds. Their explicitly appended report
  measures signal storage at 46/46 statements and 18/18 branches
  (`stored-signals-decoder.data`, `stored-signals-decoder.log`,
  `stored-signals-migration.log`).
- Ruff/format/whitespace checks pass; owned PostgreSQL stopped. No production
  source changed. Full repository coverage remains incomplete. Checkpoint 69
  remains the latest full Python baseline; a fresh aggregate run, remaining
  workspace/operational coverage and remote CI/merge verification are required.

## Ninety-third checkpoint

- Added TAIP bridge serialization tests for epoch/day UTC boundaries, exact
  credential claims, issuer/holder context, JSON roundtrip and unchanged input.
  Tests explicitly preserve the unsigned presentation placeholder and public
  signals; omission of separate SAR metadata is not confidentiality of the
  legacy circuit's public SAR signal. This does not establish standards
  conformance, completed signing or production readiness.
- Added an actual public package factory check producing two independent apps
  with working health routes. Six combined tests pass in 5.62 seconds. TAIP
  serialization measures 11/11 statements, the API initializer 4/4, and existing
  health tests retain 47/47 statements and 4/4 branches
  (`protocol-factory-complete.log`/`.data`). The broader API report is partial.
- Added installed/missing distribution metadata tests in isolated execution
  namespaces, preserving the live module's version. Two tests pass in 0.10
  seconds; version measures 5/5 statements (`version-complete.log`/`.data`).
- Ruff/format/whitespace and REUSE (720/720 files) pass. No production source
  changed. Full repository coverage remains incomplete; checkpoint 69 remains
  the latest full Python baseline. A fresh aggregate run, remaining protocol,
  generated, workspace and operational coverage and remote CI/merge are pending.


## Ninety-fourth checkpoint

- Full Python: 2245 passed, one checkpoint test skipped, 40 warnings in 464.49
  seconds. That checkpoint passes separately on its owned EVM (2.14 seconds).
  The explicit real PostgreSQL authorization/mirror scenario also passes (one
  passed, 222 deselected, six warnings in 167.03 seconds). All runners exited
  successfully; owned EVM processes are gone and PostgreSQL is stopped.
- Explicitly combined only `full-coverage-python-eleventh.data`,
  `full-coverage-checkpoint-eleventh.data` and `full-coverage-mirror-eleventh.data`,
  preserving each file. Combined JSON: `full-coverage-combined-eleventh.json`.
  Statements: 8249/8343 (98.8733%); branches: 2060/2076 (99.2293%). This adds
  95 covered statements and 56 branches over checkpoint 69.
- Generated protobufs remain 70/152 statements and 3/8 branches. Authored source
  is 8179/8191 (99.8535%) and 2057/2068 (99.4681%). Twelve authored statements
  and eleven branches remain uncovered; no new coverage exclusion was added.
- All Python test lint checks and REUSE (720/720) pass. This baseline includes
  the credential expiry source fix. Full repository coverage is not complete;
  remaining Python/generated, workspace/operational and remote CI/merge
  requirements remain open.

## Ninety-fifth checkpoint

- Added six router lifecycle/authority tests covering absent/zero verifiers,
  activation and retirement at exact timelock boundaries, unchanged pending state
  on early rejection, immediate emergency disable, future-only delay updates and
  separation of emergency pause from administrative recovery. Verification after
  unpause routes to the actual Groth16 verifier and rejects an invalid proof.
- All eight selected tests pass normally (two seconds) and instrumented. Router
  coverage reaches 100% statements, branches, functions and lines: 25 statements,
  38 branch outcomes and 12 functions (`router-boundaries-instrumented.log` and
  preserved `.json`). Other contracts in this focused report are intentionally
  partial; their aggregate coverage has not been refreshed.
- Restored normal artifacts with a forced compile; no generated bindings remain
  changed. Contract TypeScript checking passes. An initial broad run lacked the
  artifact variables and hit the default temporary directory's write quota in
  deployment output. Rerunning with the dedicated TMPDIR and explicit pilot and
  legacy bundles succeeds: all 93 contract tests pass in 48 seconds, no skips
  (`router-boundaries-full-normal-artifacts.log`).
- Whitespace checks pass. No production contract source changed. Remaining
  contract branches, other workspace and operational coverage, Python/generated
  gaps and final remote CI/merge verification keep the full goal open.

## Ninety-sixth checkpoint

- Added six sanctions-oracle tests for zero administrator, exact cooldown expiry,
  rejected inventory reduction with unchanged state, both grace-period bounds,
  oracle/admin role separation and bounded history retention. The history test
  performs 2002 actual local updates and verifies every one of the 1000 retained
  records, including root, timestamp, leaf count and chronological ring position.
  Existing staleness testing now checks equality and the next second explicitly.
- All 13 oracle tests pass normally (13 seconds). All 28 registry-file tests pass
  instrumented (37 seconds), with SanctionsOracle at 100% statements, branches,
  functions and lines: 19 statements, 24 branch outcomes and seven functions
  (`oracle-boundaries-instrumented.log` and preserved `.json`). Other contracts
  in this focused report remain partial.
- Forced normal compilation restores all generated bindings; all 28 registry-file
  tests pass again on normal bytecode (13 seconds,
  `oracle-boundaries-restored-normal.log`). TypeScript and whitespace checks pass.
  No production contract or deployed root changed. Full repository coverage
  remains incomplete: other contract branches, remaining Python/generated and
  workspace/operational paths and final remote CI/merge verification are pending.

## Ninety-seventh checkpoint

- Added five VASP registry tests covering zero admin/empty inventory, unknown or
  active reactivation, inactive discovery edits, replacement-wallet reactivation,
  stable identity/history, active counts, every registrar role gate and paused
  mutation rejection. Rejected calls preserve endpoints, counts and issuer root
  version; unpause permits reactivation and successive issuer-root updates.
- All 14 VASP tests pass normally (two seconds). All 33 registry-file tests pass
  instrumented (42 seconds). VASPRegistry reaches 100% statements, branches,
  functions and lines: 21 statements, 36 branch outcomes, 12 functions;
  SanctionsOracle retains full coverage (`vasp-boundaries-instrumented.log` and
  preserved `.json`). Other contracts in this focused report remain partial.
- Forced normal compilation restores all generated bindings. All 33 registry-file
  tests pass again on normal bytecode (14 seconds,
  `vasp-boundaries-restored-normal.log`). TypeScript and whitespace checks pass.
  No production contract source changed. Remaining contract/Python/generated,
  workspace/operational coverage and final remote CI/merge verification keep the
  full repository goal open.

## Ninety-eighth checkpoint

- Added relay constructor validation and an actual relay/oracle recovery scenario.
  Zero admin/oracle addresses reject; deployed relay binds the intended oracle.
  Pausing, excessive leaf-count reduction, revoked oracle authority and revoked
  transport authority each leave root, timestamp, count and history unchanged,
  with no RootRelayed event. Restoring authority allows exactly one successful
  relay and matching oracle history append.
- Eight relay tests pass normally (three seconds), instrumented (two seconds)
  and after restoring normal bytecode (three seconds). SanctionsRootRelay reaches
  100% statements, branches, functions and lines: six statements, six branch
  outcomes, two functions (`relay-boundaries-instrumented.log` and preserved
  `.json`; restored run `relay-boundaries-restored-normal.log`). Other contracts
  in the focused report remain partial.
- TypeScript and whitespace checks pass. Forced compilation restores all generated
  bindings. Only local test roots were exercised; production contracts and deployed
  roots are unchanged. Remaining contract/Python/generated, workspace/operational
  coverage and remote CI/merge verification keep the full repository goal open.

## Ninety-ninth checkpoint

- Added four checkpoint tests for zero scopes/admin, missing digest, unsafe
  revision, field/validity boundaries, malformed replacements and the maximum
  interoperable timestamp. Invalid replacements preserve the previous head;
  the large timestamp case restores its EVM snapshot before later tests.
- Initial measurement reached full statements but 94.12% branches. Inspection
  proved `validUntil <= validFrom` unreachable after the earlier guards require
  `validFrom <= block.timestamp < validUntil`. Removed this duplicate condition
  and documented why subtraction remains safe. Equal/reversed-window regressions
  continue to reject. No coverage exclusion or validation bypass was introduced.
- All eight focused tests pass before and after simplification. Final checkpoint
  coverage is 100% statements, branches, functions and lines: 12 statements,
  32 branch outcomes and four functions (`checkpoint-simplified-instrumented.log`
  and preserved `.json`; pre-change report `checkpoint-boundaries-instrumented`).
- Forced normal compilation regenerated the checkpoint factory from changed
  source; only that expected generated factory is included. All 110 contract
  tests pass on normal bytecode with explicit pilot/legacy artifacts in 50 seconds,
  no skips (`checkpoint-full-normal-artifacts.log`). Python's actual owned-EVM
  checkpoint integration passes in 3.25 seconds; TypeScript and whitespace pass.
- Full repository coverage remains incomplete: other contract branches, remaining
  Python/generated, workspace/operational paths and remote CI/merge verification
  still require completion. This is not a deployed-contract upgrade.


## One hundredth checkpoint

- Refreshed the complete instrumented contract suite with explicit legacy/pilot
  development artifacts: all 110 tests pass, no skips (reported duration two
  minutes, `full-contract-coverage-checkpoint100.log`). Preserved both coverage
  outputs as `full-contract-coverage-checkpoint100.json` and `-raw.json`.
- Solidity-coverage's own line map reports 378/383 lines (98.69%). Statements:
  266/271 (98.15%); branches: 293/408 (71.81%); functions: 79/83 (95.18%).
  Use the report's explicit `l` map: reconstructing lines solely from statement
  start positions with modern Istanbul produces a smaller, incorrect denominator
  for this Solidity instrumentation format.
- Remaining lines include compliance selector administration/pause/unpause,
  Pairing.P2 and a pilot-current statement rejection. Remaining branch outcomes
  are concentrated in ComplianceRegistry and PilotCurrentRegistry, plus pairing
  failure/coordinate paths in the verifier helpers. Original maps retain every
  location for follow-up; no source or coverage exclusion changed this checkpoint.
- Forced compilation restored normal artifacts and all tracked generated bindings
  match the committed state. Checkpoint 99's 110-test normal-bytecode run remains
  applicable to these identical sources/tests. The working tree has no code edits.
  Other Python/generated, workspace/operational and remote CI/merge requirements
  remain outstanding; the full goal is not complete.

## One hundred and first checkpoint

- Added three compliance-registry tests covering every missing constructor
  dependency, role-protected verifier selection/pause/recovery, and authorized
  credential revocation while proof recording is paused. Rejected calls preserve
  selector/pause state and do not create a proof record; unpause resumes ordinary
  VASP checks while retaining the revocation.
- All eight selected compliance tests pass normally (three seconds). All 36
  registry-file tests pass instrumented (42 seconds), then again after restoring
  normal bytecode (12 seconds). Previously uncovered setVerifierSelector, pause
  and unpause functions/lines are now exercised, along with all three zero-address
  constructor rejections (`compliance-admin-instrumented.log` and preserved
  `.json`, `compliance-admin-restored-normal.log`).
- The focused ComplianceRegistry report remains partial (40.54% lines, 31.11%
  branches); it does not replace checkpoint 100's complete suite report. Further
  proof-validation branches remain to test. TypeScript and whitespace pass;
  generated bindings match committed normal bytecode and no production source
  changed. Other contract/Python/generated, workspace/operational and remote
  CI/merge requirements keep the full repository goal open.

## One hundred and second checkpoint

- Extended jurisdiction observations with four malformed two-character stored
  jurisdictions, covering each ASCII bound. Added five invalid claimed codes
  (overwide, low/high first character and low/high second character) and separate
  mutations of all three threshold signals before the original valid submission.
- Every rejected submission preserves empty proof state, unused nullifier and
  empty event logs, including rollback of earlier jurisdiction observations.
  The unchanged submission then succeeds. Pairing remains explicitly mocked in
  this boundary suite; it does not establish cryptographic or legal validity.
- Seven scenarios pass normally (two seconds), instrumented (four seconds) and
  after restoring normal bytecode (two seconds). Both outcomes of every targeted
  jurisdiction and threshold comparison are covered, including previously missed
  encoder returns (`jurisdiction-boundaries-instrumented.log` and preserved
  `.json`, `jurisdiction-boundaries-restored-normal.log`). The focused registry
  report remains partial: 89.19% lines and 60% branches.
- TypeScript and whitespace checks pass; generated bindings match committed
  normal bytecode. No production source changed. Other proof-validation branches,
  contract/Python/generated, workspace/operational and remote CI/merge requirements
  remain open for the full repository goal.

## One hundred and third checkpoint

- Added eight signal-binding rejections (chain, contract, expiry, future timestamp,
  sanctions/issuer roots, transfer and revoked credential), plus paused dependency,
  wrong-wallet and unset-selector checks to the existing controlled-pairing
  scenario. Every failure preserves absent proof state, unused nullifier and
  empty proof/observation event logs before the unchanged submission succeeds.
- After success, exact transfer replay and a correctly rebound second transfer
  with the same nullifier reject; the second record remains absent and exactly
  one ProofVerified event exists. Pairing is explicitly mocked in this suite;
  separate artifact suites establish cryptographic behavior.
- Seven scenarios pass normally (three seconds), instrumented (six seconds) and
  after normal-bytecode restoration (two seconds). Focused ComplianceRegistry
  coverage reaches 94.59% lines and 78.89% branches
  (`legacy-binding-instrumented.log` and preserved `.json`,
  `legacy-binding-restored-normal.log`); this is not a replacement full report.
- TypeScript and whitespace pass; normal generated bindings are unchanged.
  No production source changed. Remaining validation/cryptographic branches,
  other contract/Python/generated, workspace/operational and remote CI/merge
  requirements keep the full repository goal open.

## One hundred and fourth checkpoint

- Routed the rejection scenario through an actual Groth16 verifier. Initial
  validation showed malformed points revert at the pairing precompile rather
  than returning false. Tests now distinguish that error from canonical infinity
  points that produce a negative pairing result and ProofVerificationFailed.
  Both paths preserve records/nullifiers/events before the controlled positive
  registry flow resumes. No production defect or source change was inferred.
- All 53 registry/jurisdiction/threshold tests pass instrumented (57 seconds),
  then again on restored normal bytecode (21 seconds). ComplianceRegistry now
  measures 100% lines/statements/functions and 98.89% branches
  (`compliance-pairing-boundaries-complete.log`/`.json`,
  `compliance-pairing-restored-normal.log`).
- The sole remaining branch is the missing-default threshold guard at line 172:
  normal construction and setters always register the fallback. It remains
  explicitly pending invariant review; no storage corruption or exclusion was
  introduced to claim coverage. Other contracts in this focused report are not
  a new full baseline.
- TypeScript and whitespace pass; normal generated bindings are unchanged.
  Other contract/Python/generated, workspace/operational and remote CI/merge
  requirements keep the full repository goal open.

## One hundred and fifth checkpoint

- Audited all threshold-table writes: construction seeds the fallback, the sole
  writing helper always sets registered=true, and there is no deletion or other
  mutation path. Added a public-API invariant test for default/explicit resolution,
  accepted updates at uint64 boundaries, rejected ordering and unauthorized
  updates. All 11 threshold tests pass before simplification (three seconds).
- Removed the redundant missing-fallback guard from proof verification and
  documented the maintained invariant. Threshold ordering, authorization and
  comparisons against all three proof signals remain unchanged. No corrupted
  storage setup or coverage exclusion was introduced.
- All 54 combined registry/jurisdiction/threshold tests pass instrumented in
  58 seconds. ComplianceRegistry reaches 73/73 lines, 67/67 statements, 88/88
  branch outcomes and 14/14 functions (`compliance-invariant-complete.log`/`.json`).
- Forced normal compilation regenerates only the expected compliance-registry
  factory. All 118 contract tests pass with actual pilot/legacy artifacts in
  51 seconds, no skips (`compliance-invariant-full-normal.log`). TypeScript and
  whitespace pass. This source change is local, not a deployed-contract upgrade.
- Other contract/Python/generated, workspace/operational and remote CI/merge
  requirements remain incomplete; the full repository goal stays open.

## One hundred and sixth checkpoint

- Added current-registry constructor/publisher checks and 13 malformed head-update
  cases: missing scope/digest, future/expired/oversized validity, scalar bound,
  wrong expected revision and invalid values for non-root/authorization kinds.
  Unauthorized calls preserve publisher configuration and rejected publication
  leaves no new head or event. Accepted scalar limits, monotonic time and disabled
  replacement state are verified through actual contract calls.
- All 19 dedicated current-registry tests pass with real development artifacts:
  normally in 11 seconds, instrumented in 23 seconds and after normal restoration
  in 12 seconds. Current-registry coverage is 100% lines/statements/functions and
  68.49% branches (`current-head-boundaries-instrumented.log` and preserved `.json`,
  `current-head-boundaries-restored-normal.log`). Statement/pin/currentness and
  other defensive branches still require tests; other contracts are partial in
  this focused report.
- TypeScript and whitespace pass; generated bindings match committed normal
  bytecode. No production source changed. Remaining contract/Python/generated,
  workspace/operational and remote CI/merge requirements keep the full goal open.

## One hundred and seventh checkpoint

- Added ten invalid statement metadata cases and six pin faults for each of the
  seven required current heads (42 pin cases). Missing/unknown scopes, missing or
  mismatched digests and invalid revisions reject without retaining an approval,
  emitting a statement event or changing the original checkpoint.
- The corrected metadata publishes successfully; corrected pins also pass actual
  pairing inspection using the existing development proof. These tests exercise
  authenticated publisher input boundaries, not source JSON/Ed25519 authentication.
- All 21 current-registry tests pass normally (12 seconds), instrumented (31
  seconds) and after restoring normal bytecode (12 seconds). Branch coverage
  increases from 68.49% to 82.88%; line/statement/function coverage remains 100%
  (`current-statement-boundaries-instrumented.log` and preserved `.json`,
  `current-statement-boundaries-restored-normal.log`). Other contracts in this
  focused report remain partial.
- TypeScript and whitespace pass; normal generated bindings are unchanged.
  No production source changed. Remaining inspection/currentness/batch branches,
  other contract/Python/generated, workspace/operational and remote CI/merge
  requirements keep the full repository goal open.

## One hundred and eighth checkpoint

- Added inspection/mirroring rejection for unknown statement IDs, a relabeled
  tenant deliberately configured with the same publisher/epoch, and proof expiry
  extending beyond the approved statement window. Both inspection and mirroring
  reject; neither tenant acquires a mirrored receipt or event. The original
  valid proof still inspects and mirrors exactly once for its proper tenant.
- All 22 current-registry tests pass normally (12 seconds), instrumented (32
  seconds) and after restoring normal bytecode (12 seconds). Branch coverage
  increases to 86.30%; lines/statements/functions remain 100%
  (`current-inspection-boundaries-instrumented.log` and preserved `.json`,
  `current-inspection-boundaries-restored-normal.log`). Other contracts in this
  focused report remain partial.
- TypeScript and whitespace pass; generated bindings match committed normal
  bytecode. No production source changed. Remaining currentness/batch/defensive
  branches, other contract/Python/generated, workspace/operational and remote
  CI/merge requirements keep the full repository goal open.

## One hundred and ninth checkpoint

- Added seven batch consistency faults after a valid early head replacement:
  mismatched pin scope/digest and altered reused-head digest/value/validity/enabled
  state. Claimed digest is deliberately aligned for the retained-digest case so
  it tests the retained-head comparison rather than an earlier pin check.
- Every failure rolls back all eight heads and head/statement events, retains no
  approval and creates no mirrored receipt. The corrected batch advances the
  intended revisions and its resulting statement passes actual proof inspection.
- All 23 current-registry tests pass normally (11 seconds), instrumented (30
  seconds) and after restoring normal bytecode (12 seconds). Branch coverage
  reaches 92.47%; lines/statements/functions remain 100%
  (`current-batch-boundaries-instrumented.log` and preserved `.json`,
  `current-batch-boundaries-restored-normal.log`). Other contracts remain partial
  in this focused report.
- TypeScript and whitespace pass; normal generated bindings are unchanged.
  No production source changed. Remaining currentness/defensive branches, other
  contract/Python/generated, workspace/operational and remote CI/merge requirements
  keep the full repository goal open.

## One hundred and tenth checkpoint

- Added rejection of source heads published after proof evaluation for each of
  the six evaluation-time evidence kinds. Failed statements retain no approval
  or publication event; the original statement still passes actual proof inspection.
- Added exact head-expiry rejection while its approved statement remains live.
  Inspection succeeds before the deadline; inspection and mirroring reject at
  expiry, preserving the approval without creating a receipt or mirror event.
- All 25 current-registry tests pass normally (10 seconds), instrumented (12
  seconds), and after restoring normal bytecode. Focused coverage reaches 94.52%
  branches with 100% lines/statements/functions for PilotCurrentRegistry
  (`current-head-time-instrumented.log` and preserved `.json`,
  `current-head-time-restored-normal.log`). This is not a repository-wide result.
- TypeScript and whitespace checks pass; generated bindings match committed
  normal bytecode. No production source changed. Eight uncovered branch outcomes
  remain in this contract, including defensive dependency and invariant checks.
  Other contracts, Python/generated code, workspace/operational coverage and
  remote CI/merge requirements keep the full goal open.

## One hundred and eleventh checkpoint

- Added explicit verifier-dependency fault injection: a zero-return runtime
  exercises constructor rejection of an empty artifact manifest; replacing the
  pinned verifier's runtime exercises code-hash mismatch rejection in inspection
  and mirroring. No registry storage or proof inputs are modified.
- Faulted inspection/mirroring retains the statement but creates no receipt or
  event. Both injected runtimes are restored in finally blocks; the original
  verifier subsequently inspects the real proof and mirrors exactly once.
- All 26 current-registry tests pass normally (7 seconds), instrumented (14
  seconds), and after normal-bytecode restoration. Focused branch coverage is
  95.89%, with 100% lines/statements/functions for this contract
  (`current-verifier-dependency-instrumented.log` and preserved `.json`,
  `current-verifier-dependency-restored-normal.log`). Dependency fault injection
  tests a defensive boundary; it does not claim deployed immutable code can
  ordinarily be replaced through the contract's public API.
- TypeScript and whitespace checks pass. Normal generated bindings are unchanged;
  no production source changed. Remaining invariant/revision branches and the
  broader repository coverage, operational and remote requirements remain open.

## One hundred and twelfth checkpoint

- Refreshed full Solidity instrumentation with both explicit legacy and pilot
  development artifact bundles: all 127 tests pass with no skips. Aggregate
  coverage is 381/382 lines (99.74%), 269/270 statements (99.63%), 392/406
  branches (96.55%) and 82/83 functions (98.80%). Line counts preserve the
  Solidity report's explicit line map rather than reconstructing statement lines.
- Preserved full reports as `full-contract-coverage-checkpoint112.json` and
  `full-contract-coverage-checkpoint112-raw.json`, with the corresponding log.
  Restored normal bytecode and ran the entire 127-test suite successfully with
  both real-proof artifact bundles, again with no skips (`-normal.log`).
- Remaining uncovered outcomes: three Pairing input/precompile error branches
  and its P2 function; six current-registry invariant/revision branch outcomes;
  two pilot-verifier key-validation outcomes; three BLS benchmark input/precompile
  errors. None is excluded from reporting. The source inventory above now uses
  this full aggregate instead of older focused estimates.
- TypeScript and whitespace checks pass, and generated normal bindings remain
  unchanged. No production source changed. Full repository coverage remains
  unproven; other languages/workspaces, operational coverage and remote CI/merge
  still require completion evidence.

## One hundred and thirteenth checkpoint

- Added BLS verifier input-boundary checks using the actual committed proof:
  empty, 511-byte and 513-byte proofs reject with the proof-length error;
  zero, 15 and 17 signals reject with the signal-count error. The original
  512-byte/16-signal proof still verifies after all rejected calls.
- All four BLS benchmark tests pass normally (1 second), instrumented (3 seconds)
  and after restoring normal bytecode (1 second). Focused BLS coverage increases
  from 62.5% to 87.5% branches with 100% lines/statements/functions
  (`bls-input-boundaries-instrumented.log` and preserved `.json`,
  `bls-input-boundaries-restored-normal.log`). Its MSM-precompile failure outcome
  remains uncovered; this report is not the full contract aggregate.
- TypeScript and whitespace pass; generated normal bindings are unchanged.
  No production source changed. Other Solidity and repository-wide gaps,
  operational verification and remote CI/merge remain required for completion.

## One hundred and fourteenth checkpoint

- Added subprocess checks for both Python and upb protobuf implementations.
  A synthetic sealed envelope retains identical deterministic bytes, including
  an unknown wire field, through each backend. Checks also cover error enum
  aliases, oneof replacement/clearing, nested-message roundtrip and RPC descriptor
  streaming/type metadata. Runtime selection is verified inside each fresh child.
- Both new cases and the existing gRPC bridge suite pass: 24 tests, 9 warnings,
  7.43 seconds (`protobuf-runtime.log`). Subprocess coverage is captured in
  `protobuf-runtime.data` and `.json`. Generated message modules reach 48/48 and
  21/21 statements, each with 2/2 branches. No generated source was edited.
- Importing the generated errors gRPC module covers its supported-runtime path
  (9/12 statements, 1/2 branches). Generated service handlers and incompatible
  runtime paths remain incomplete; this focused run does not replace the full
  Python aggregate. All source remains in the coverage denominator.
- Ruff and whitespace pass; REUSE covers all 721 files. Full repository coverage,
  remaining operational checks and remote CI/merge remain open.

## One hundred and fifteenth checkpoint

- Added owned loopback gRPC servers registering the generated network and health
  servicers. Both regular stubs and experimental client helpers exercise all five
  RPCs and assert the exact UNIMPLEMENTED status/details, including streamed
  failures. Every server is stopped and its worker pool joined. This synthetic
  dispatch test makes no production mTLS or compliance claim.
- Added isolated subprocess dependency faults for both generated gRPC modules:
  an old advertised runtime version and a missing version helper. Tests verify
  the actual warning-versus-error behavior and actionable module/version text.
  No generated file is edited and the parent interpreter is unaffected.
- All 38 selected tests pass, 11 warnings, 14.54 seconds
  (`generated-grpc-complete.log`, `.data`, `.json`). All four generated protobuf
  modules now measure 152/152 statements and 8/8 branches in this focused report.
  The prior full Python aggregate must still be refreshed with these tests.
- Ruff/whitespace pass; REUSE accounts for all 722 files. Authored Python gaps,
  remaining Solidity/workspace and operational coverage, and remote CI/merge
  remain incomplete. The full repository goal stays open.

## One hundred and sixteenth checkpoint

- Added empty and oversized root-certificate tests using an actual synthetic
  certificate chain. Valid timing trust loads before and after each rejection;
  invalid roots pass schema loading but fail trust construction with the exact
  certificate-size error. The CLI returns only its minimized indeterminate report.
- The initial test run exposed an incorrect test assumption about public trust
  attributes, not a production defect; assertions now use the actual construction
  interface. The complete history CLI/timestamp suite passes 59 tests, 5 warnings,
  15.76 seconds (`history-root-size-complete.log`, `.data`, `.json`). The previously
  uncovered size-rejection statement and branch execute without mocked parsing.
- Focused history_cli coverage is 99/108 statements and 11/14 branches. Other
  paths depend on the wider real-artifact history suite; no full aggregate claim
  is made from this selection. Ruff and whitespace pass; production unchanged.
- Full Python aggregation, remaining authored and Solidity/workspace coverage,
  operational verification and remote CI/merge keep the repository goal open.

## One hundred and seventeenth checkpoint

- Added explicit zero-registry rejection for current root pins. The valid pins
  still validate and all three actual signed root snapshots verify afterward.
- Added issuance-tree zero-registry rejection through the public async builder.
  A transaction boundary spy proves it rejects before any tenant authorization
  or storage access; valid context construction succeeds before and afterward.
- All 19 selected tests pass, 5 warnings, 7.44 seconds
  (`root-scope-validation.log`, `.data`, `.json`). Pilot root verification reaches
  37/37 statements and 8/8 branches. The issuance context's previously missing
  rejection is covered; this focused suite does not execute its PostgreSQL tree
  construction paths and does not replace full-suite evidence.
- Ruff, whitespace and REUSE pass. No production changes or coverage exclusions.
  Full Python aggregation, remaining authored and Solidity/workspace gaps,
  operational checks and remote CI/merge keep the repository goal open.

## One hundred and eighteenth checkpoint

- Added seven witness-builder rejection cases: credential tenant/wallet/jurisdiction
  mismatch, unsupported proof profile and wrong depth for each of the three trees.
  Fixture inputs are recorded while executing the real builder, not substituted
  with mocked outputs; all negative cases rebuild the original valid witness
  afterward and compare it exactly with the control.
- The full composed-witness test module passes 28 tests with no skips, including
  actual Circom compilation and WASM adversarial witness generation, in 44.82
  seconds (`witness-builder-boundaries-complete.log`, `.data`, `.json`). The
  builder reaches 36/36 statements and 10/10 branches. No generated circuit
  artifacts or production source changes are included.
- Ruff and whitespace pass. This is focused evidence; full Python aggregation,
  remaining authored/other-workspace gaps, operational checks and remote CI/merge
  remain required before the repository coverage goal can be complete.

## One hundred and nineteenth checkpoint

- Audited the remaining unused proof-route hashing helper: repository search finds
  no caller. Removed that private helper; active transfer identifiers and hashing
  paths are unchanged and still use hashlib.
- Audited the duplicate valuation quotient check. Transfer's always-revalidated
  model enforces the same integer equation before witness calculation, including
  model_copy inputs. Strengthened the existing large-integer regression to assert
  that specific validation error; it passes before source cleanup. Removed only
  the unreachable duplicate check and documented its upstream invariant.
- All 92 valuation/API/route-failure tests pass, 5 warnings, 13.54 seconds, including
  actual Circom/WASM arithmetic checks (`valuation-invariant-complete.log`, `.data`,
  `.json`). Valuation witness coverage is 14/14 statements and 4/4 branches.
  Proof-route coverage is partial in this selection and still needs the wider
  PostgreSQL suite. The source denominator is now 8338 statements/2074 branches;
  old aggregate coverage files describe the previous source revision.
- Ruff and whitespace pass. No exclusions or generated-artifact changes. Full
  Python aggregation, remaining authored/other-workspace and operational coverage,
  and remote CI/merge requirements keep the full goal open.


## One hundred and twentieth checkpoint

- Full Python run with real PostgreSQL, both development proof bundles and policy
  CLI enabled: 2272 passed, one skipped, 42 warnings in 471.55 seconds
  (`full-coverage-python-twelfth.log`, `.data`, `.json`). The skipped checkpoint
  test passes separately on its owned EVM: one passed, two warnings, 3.37 seconds.
- The optional authorization/mirroring path passes separately against PostgreSQL
  and its owned EVM: one passed, 222 deselected, six warnings, 165.37 seconds.
  All three processes exit zero; owned EVMs have exited and PostgreSQL is stopped.
- Combined exactly those three data files, retaining the originals. The resulting
  `full-coverage-combined-twelfth.data` and `.json` report 8335/8338 statements
  (99.964%) and 2070/2074 branches (99.807%). All generated protobuf code stays
  included and fully covered. Three statements/four branches remain, inventoried
  above. The pre-existing one-line exclusion is unchanged.
- Full source/test Ruff and REUSE checks pass (723/723 files); generated bindings
  and tracked worktree files remain unchanged by test execution. This refresh
  replaces older Python aggregates, not other workspace evidence. Remaining
  Python and Solidity/workspace gaps, operational coverage and remote CI/merge
  still prevent completion of the full repository goal.

## One hundred and twenty-first checkpoint

- Added transaction-boundary fault injection for an observation ID whose record
  disappears during scanning. The actual service raises the precise error and
  exits its transaction without returning a partial page. Restoring the synthetic
  record produces a correctly decoded page and exits the second transaction.
- Added fresh-process bilateral CLI import checking no output and unchanged stdin
  position. This exercises the module's non-command entry path without running
  its CLI. Existing actual CLI execution coverage remains in the full report.
- All 83 selected unit/observation HTTP tests pass, 5 warnings, 14.40 seconds
  (`python-last-boundaries-complete.log`, `.data`, `.json`). Ruff, whitespace and
  REUSE pass (724/724 files). No production source changed.
- Combined this focused data with checkpoint 120's full/EVM aggregate because
  production source is identical. `python-checkpoint121-combined.data`/`.json`
  measure 8336/8338 statements and 2072/2074 branches. This is an incremental
  aggregate, not a new full-suite run. Only discovery reconstruction and frozen
  projection length remain uncovered in Python. Other workspace/operational and
  remote CI/merge requirements keep the full goal open.

## One hundred and twenty-second checkpoint

- Audited discovery reconstruction: accepted authority syntax permits only the
  canonical uppercase %3A port escape, and path validation preserves every path
  component. Reconstructing an accepted DID cannot differ from its input. Added
  36 host/port/path identity-preservation cases, including punycode and numeric
  paths; those and five existing projection inventory/immutability cases pass
  before cleanup (41 passed, 174 deselected, 0.33 seconds).
- Simplified discovery to retain the already validated DID directly. Removed the
  repeated projection length check: construction requires an exact 48-field tuple
  and frozen instances preserve it. Boundary validation remains unchanged; no
  corrupted object state or exclusions are used to manufacture coverage.
- All 234 discovery, local TLS transport and actual projection Circom/WASM tests
  pass without skips, five warnings, 39.00 seconds (`python-invariants-complete.log`,
  `.data`, `.json`). Discovery reaches 92/92 statements and 42/42 branches;
  projection reaches 50/50 statements and 12/12 branches. Ruff/whitespace pass.
- Source totals are now 8332 statements/2068 branches. Previous aggregates cover
  an older revision and must not be reused as proof of full coverage of this one.
  A fresh full Python/EVM run remains required, as do other workspace, operational
  and remote CI/merge requirements. The full repository goal remains open.

## One hundred and twenty-third checkpoint

- Added real local TLS discovery acceptance without Content-Encoding, and a
  delayed DNS result released only after the request deadline. The latter opens
  no connection; a subsequent independent request succeeds against the same server.
- Full SDK coverage run passes with 514/517 statements (99.41%), 666/671 branches
  (99.25%), 400/400 lines and 89/89 functions. Evidence is preserved in
  `sdk-transport-boundaries.log`, `-summary.json` and `.lcov`. Transport reaches
  100% statements; its missing-status fallback remains uncovered.
- TypeScript and whitespace pass. No production source changed. Remaining SDK
  canonical/profile/cohort and transport outcomes, the pending full Python rerun,
  Solidity and operational coverage, and remote CI/merge keep the full goal open.

## One hundred and twenty-fourth checkpoint

- Added HTTP dependency fault injection for an absent response status. The actual
  transport rejects with unavailable/HTTP 0 and destroys the request exactly once;
  a valid subsequent response resolves parsed JSON and also closes its request.
  Existing real TLS tests remain in the full SDK run. No production source changed.
- All 214 SDK tests pass in 2.63 seconds. Transport now has 100% of every coverage
  metric; aggregate SDK coverage is 514/517 statements, 667/671 branches, 400/400
  lines and 89/89 functions (`sdk-response-boundary.log`, preserved `-summary.json`
  and `.lcov`). TypeScript, whitespace and REUSE pass.
- Remaining serialization/profile/cohort outcomes, the full Python rerun,
  Solidity/operational verification and remote CI/merge still prevent completion
  of the full repository goal.

## One hundred and twenty-fifth checkpoint

- Added SDK identity-preservation checks for 36 canonical DID host/port/path
  combinations, matching the Python cases. The test passes before source cleanup.
  Validation already preserves every accepted component, so discovery now returns
  the validated DID directly rather than reconstructing and comparing it.
- Added trailing LF/CR/CRLF object-key rejection cases. These pass but do not add
  branch coverage: direct runtime checks confirm the existing non-multiline ASCII
  regex already rejects them. The explicit newline condition remains unchanged
  in this commit; no claim is made that these cases exercised that condition.
- All 215 SDK tests pass. Aggregate coverage is 512/514 statements, 664/667 branches,
  399/399 lines and 88/88 functions (`sdk-canonical-profile-complete.log`, preserved
  `-summary.json` and `.lcov`). TypeScript and whitespace pass. Discovery profile
  now has full coverage; canonical/cohort outcomes remain for invariant review.
- Full Python rerun, remaining Solidity/workspace and operational evidence, and
  remote CI/merge are still required. The full repository goal stays open.

## One hundred and twenty-sixth checkpoint

- Consolidated identical lexical comparators for canonical keys and cohort IDs
  into one internal helper. Direct ordering tests cover all pairings of punctuation,
  numeric-looking identifiers and mixed case, including equality and duplicate
  inputs. Removed the redundant object-key newline predicate after the existing
  ASCII regex and explicit CR/LF rejection tests established its invariant.
- Detailed Istanbul data exposed additional reachable gaps: oversized/hidden-key
  objects and cache eviction. Added exact 64-key acceptance, 65-key/symbol/nonenumerable
  rejection and an actual local TLS test with 129 identities. Refreshing entry zero
  retains it while entry one is evicted; retained entries require no request and
  the evicted entry requires a new request.
- Full SDK gated run: 218 passed, 6.28 seconds, 515/515 statements, 661/661 branches,
  400/400 lines and 89/89 functions. Preserved `sdk-complete-checkpoint126-gated.log`,
  `-summary.json` and `.json`. TypeScript and whitespace pass. The coverage command
  now enforces 100% statements/branches as well as existing line/function gates.
- This completes measured SDK source coverage, not repository completion. Full
  Python rerun, Solidity gaps, operational/browser coverage and remote CI/merge
  remain required. The full goal stays open.

## One hundred and twenty-seventh checkpoint

- Expanded actual pilot-verifier constructor checks for all three G2 key slots:
  infinity rejects with InvalidKey and off-curve points reject through the pairing
  precompile. Added off-curve G1 key rejection through the scalar precompile.
  The original independent verifier still accepts its real proof afterward.
- All three pilot verifier tests pass normally (3 seconds), instrumented (13
  seconds) and after normal-bytecode restoration (4 seconds). Focused verifier
  branch coverage rises to 93.75%, with 100% statements/lines/functions
  (`pilot-key-boundaries-instrumented.log` and preserved `.json`,
  `pilot-key-boundaries-restored-normal.log`). Pairing's scalar-precompile failure
  outcome is also exercised. Other Pairing paths remain partial in this selection.
- TypeScript and whitespace pass; normal generated bindings are unchanged.
  No production source or proving artifacts changed. The final defensive G2
  pairing-result outcome, other Solidity gaps, full Python rerun, operational
  checks and remote CI/merge keep the full repository goal open.

## One hundred and twenty-eighth checkpoint

- Added a test-only Pairing harness with normal generated bindings. Tests exercise
  actual EVM precompiles: canonical generators, infinity, double negation, inverse
  addition, multiplication identities, empty pairing, a false single pairing and
  cancellation. Both length-mismatch directions and off-curve addition/scalar/
  pairing operands reject with exact errors; valid multiplication still succeeds.
- Two tests pass normally (2 seconds), instrumented (under one second), and after
  restoring normal bytecode. Focused Pairing branch coverage is 100%; its
  pairingProd4 wrapper is exercised by verifier suites rather than this harness,
  so focused line/function coverage remains partial. Harness coverage is 100%.
  Evidence: `pairing-library-instrumented.log`/`.json` and `-restored-normal.log`.
- Initial TypeScript errors from positional struct arguments were corrected to
  named ABI fields. Final typecheck, whitespace and REUSE pass. Only the new
  harness bindings and normal generated indexes change; existing verifier
  factories remain unchanged. No proving artifacts or deployments changed.
- Full Solidity aggregation, remaining verifier/registry defensive branches,
  full Python rerun, operational checks and remote CI/merge remain required.

## One hundred and twenty-ninth checkpoint

- Exercised BLS MSM precompile failure using the actual valid proof and a bounded
  100000-gas call. It returns the exact G1MSM failure, while the unchanged proof
  succeeds afterward with the normal allowance. No precompile or key was mocked.
- All five BLS tests pass normally (1 second), instrumented (6 seconds) and after
  restoring normal bytecode (2 seconds). BLS verifier coverage reaches 100% in all
  four metrics (`bls-msm-gas-instrumented.log` and preserved `.json`,
  `bls-msm-gas-restored-normal.log`). This is focused contract evidence; no gas
  pricing or production readiness claim follows from coverage instrumentation.
- TypeScript and whitespace pass; normal generated bindings match committed
  bytecode. Production source is unchanged. Remaining current-registry/pilot
  verifier branches, full Python and Solidity aggregation, operational coverage
  and remote CI/merge keep the full repository goal open.

## One hundred and thirtieth checkpoint

- Added caller revision boundary cases at MAX_SAFE, MAX_SAFE+1 and uint64 maximum.
  Rejections preserve the existing head and events; a correct current revision
  still advances it once. All 27 current-registry tests pass before source change.
- Reordered the existing revision predicates to validate the caller's bound before
  comparing stored state. Accepted/rejected inputs and error type are unchanged;
  the bound is now independently exercised without corrupting registry storage.
- Instrumentation exposed an existing wall-clock timing flaw: a short-lived head
  could expire before its publication transaction. Explicitly pinned the two
  publication block timestamps; the exact expiry assertion remains unchanged.
- Corrected focused instrumentation passes 27 tests in 34 seconds, reaching 97.26%
  branches and 100% other current-registry metrics (`current-revision-instrumented-
  complete.log`/`.json`). Restored normal bytecode, then the full Solidity suite
  passes 132 tests with both real proof bundles and no skips in 53 seconds
  (`current-revision-full-normal.log`). TypeScript/whitespace pass.
- Only the expected normal current-registry factory changes. Remaining temporal
  invariants, pilot verifier defensive pairing result, full coverage aggregation,
  Python rerun, operational checks and remote CI/merge keep the full goal open.

## One hundred and thirty-first checkpoint

- Audited every current-registry head/approval write. Head validation already
  enforces validFrom <= now < validUntil, so the explicit validUntil <= validFrom
  rejection is redundant and subtraction remains safe. Statement evaluation time
  is checked before its only immutable approval write; batch publication routes
  through that same function. Monotonic chain time preserves that invariant during
  inspection. Removed only these repeated predicates and documented the reasoning.
- Existing malformed-time, future-evaluation, exact-expiry, publication rollback
  and real-proof tests remain unchanged. All 27 focused instrumented tests pass in
  36 seconds with 100% current-registry lines/statements/branches/functions
  (`current-time-invariants-instrumented.log` and preserved `.json`).
- Restored normal bytecode and verified the entire 132-test Solidity suite with
  both real proof bundles, no skips (`current-time-invariants-full-normal.log`).
  TypeScript and whitespace pass; only the expected normal registry factory is
  regenerated. No production proving material or deployment changes.
- The pilot verifier's defensive pairing result remains for audit. Full aggregate
  reports, Python rerun, operational/browser requirements and remote CI/merge
  still prevent completion of the full repository coverage goal.


## One hundred and thirty-second checkpoint

- Preserved the pilot verifier's defensive pairing-result check. Added isolated
  fault injection through the installed Hardhat EDR call-override hook, restricted
  to address 0x08. A false precompile result rejects construction with InvalidKey;
  the hook is restored in finally and the original real proof verifies afterward.
  The test explicitly fails if this internal Hardhat capability disappears.
- Full Solidity instrumentation passes all 133 tests with both real proof bundles
  and no skips: 387/387 lines, 275/275 statements, 402/402 branches and 88/88
  functions, all 100%. Preserved `full-contract-coverage-checkpoint132.log`, `.json`
  and `-raw.json`. Counts use the original Solidity line map.
- Restored normal bytecode and all 133 tests pass again in 52 seconds
  (`full-contract-coverage-checkpoint132-normal.log`). TypeScript and whitespace
  pass; generated bindings remain unchanged. No production source changed.
- This completes local measured Solidity coverage, not the repository goal.
  Full Python rerun, coverage CI gates/artifact retention, operational/browser
  checks and remote CI/review/merge verification remain required.

## One hundred and thirty-third checkpoint

- Added Solidity coverage gates for all four metrics using the installed
  sc-istanbul CLI supplied by solidity-coverage. The complete current report
  passes; independent temporary reports with one uncovered statement, branch,
  function or line each fail with exit 1 (`coverage-gate-negative-*.log`).
  This verifies the original Solidity line map as well as statement counts.
- The CI circuit job now runs gated full coverage after creating both fresh proof
  bundles and completing its durable mirror check. It restores normal bytecode
  even on failure, runs full normal-bytecode verification on success, and uploads
  coverage evidence with seven-day retention even when coverage fails.
- Workflow YAML and whitespace checks pass. No application/test source changed;
  checkpoint 132 remains the current full local Solidity execution evidence.
  Remote workflow execution is not yet verified. Full Python rerun, remaining
  operational/browser verification and remote CI/review/merge keep the goal open.

## One hundred and thirty-fourth checkpoint

- Full Python refresh finishes with exit 0: 2310 passed, one skipped and 42
  warnings in 466.94 seconds. The skipped checkpoint passes on its owned local
  EVM (one passed, two warnings, 3.25 seconds). The explicit durable authorization
  mirror path passes with real PostgreSQL, proof and EVM (one passed, 222
  deselected, six warnings, 162.40 seconds).
- Combined exactly those three coverage databases. All 143 source files have
  zero missing lines and branches: 8332/8332 statements and 2068/2068 branches.
  Generated protobufs remain included. Evidence is preserved externally as
  `full-coverage-{python,checkpoint,mirror,combined}-thirteenth.*`; no generated
  proving material is committed. Owned PostgreSQL stopped; no test EVM remains.
- Ruff passes and REUSE covers all 729 tracked files. The exact 100% coverage
  CLI gate passes against the aggregate. Its installed threshold implementation
  also rejects 99.999999%, preventing rounding from concealing a missing branch.
- The circuit CI job now measures its existing durable mirror run, builds the
  SDK/CLI, runs full Python tests with PostgreSQL and both fresh proof profiles,
  runs checkpoint coverage, and combines the three named databases before the
  100% gate. Raw data and aggregate JSON are retained even on failure. Workflow
  YAML parses and all referenced workspace build commands exist; remote execution
  is still unverified.
- This completes local measured Python source coverage. Operational scripts,
  rendered docs/browser behavior and remote CI/review/merge remain required;
  the full repository goal stays open.

## One hundred and thirty-fifth checkpoint

- Added a separate Playwright suite with its locked browser dependency. It
  discovers all 16 MDX pages, checks their headings/navigation/footer/language,
  rejects page/console errors and verifies the logo on desktop/mobile Chromium.
  The Mermaid page must render its actual SVG. A navigation/back test verifies
  that client navigation preserves a window marker; unknown pages return 404.
- Production HTTP tests exercise the manifest and every topic, recipe and signal
  against the real content package, plus bounded missing-entry errors. These
  verify workspace content assets through the built server, beyond direct route
  handler unit calls. No remote service or deployed site is mutated.
- The production build passes; 38 browser/server checks pass in 16.5 seconds
  (`docs-e2e-checkpoint135.log`). Initial harness setup needed CommonJS-compatible
  directory resolution and installation of the locked Chromium build. No page
  source changes were necessary. The owned server terminates with the runner.
- All 50 docs unit tests still pass, covering 26/26 statements and lines, 6/6
  branches and 6/6 functions. TypeScript and workflow YAML validation pass.
  Build/unit reports are `docs-{build,unit}-checkpoint135.log` outside the repo.
- Added a Node 24 CI browser job with a production build, Chromium installation,
  and retained HTML reports/failure traces. Documented commands and ignored
  generated reports. Remote execution, other browser engines, deployment tracing,
  operational scripts and the final CI/review/merge audit remain unfinished.

## One hundred and thirty-sixth checkpoint

- Inventoried all 17 operational executables separately from application source
  in `OPERATIONAL_TEST_INVENTORY.md`. Ten Python scripts contain 1045 statements
  and 238 branches; the four JavaScript and three shell scripts are explicit
  separate obligations. Existing focused tests initially covered 366 statements
  and 68 branches. This is a measured gap, not completed repository coverage.
- Added real HPKE key-generator tests: silent import, executable entry, distinct
  keys, independently derived X25519 public keys and SHA-256 fingerprints, actual
  HPKE encryption/decryption, and a foreign-directory subprocess with no output
  files. Ephemeral private output stays captured inside tests. All 15 statements
  and both branches of the generator are covered. An initial filesystem assertion
  counted the pre-existing shared fixture directory; corrected by creating a
  dedicated empty working directory. Module-name coverage was also replaced with
  the whole scripts source path so runpy execution is measured correctly.
- Added 12 real Node Poseidon helper tests: both input formats with large decimal
  strings, a large whitespace stdin prefix, and malformed JSON, shapes, values
  and arity. Valid output agrees with native Python Poseidon; failures return
  nonzero with no hash on stdout. No live sanctions source/root is changed.
- The exact focused CI command passes 61 tests in 28.71 seconds. Its all-script
  Python report measures 381/1045 statements and 70/238 branches, with no
  exclusions (`scripts-combined136.log`/`.json`). JS subprocess acceptance is
  reported separately, without pretending Python instrumentation covers Node.
- Added an operational CI job and retained partial report, without a premature
  100% gate. Ruff, whitespace, workflow parsing and REUSE (734 files) pass.
  Remaining script branches, browser/deployment audit and remote CI/review/merge
  continue to keep the original full-coverage goal open.

## One hundred and thirty-seventh checkpoint

- Expanded the L2 historical cost-model tests with identical-payload crossover
  boundaries (already inverted/tied/never), zero-cost share, unsupported chain
  rejection, both Markdown threshold labels and finite historical sensitivity
  thresholds. Placeholder inputs must be deterministic and visibly warned.
- Synthetic measured inputs preserve exact transaction bytes without a warning.
  Both CLI report formats run through the actual entry point. JSON contains all
  18 chain/regime/system combinations and consistent execution/DA/USD totals;
  Markdown identifies measured gas, byte sizes and all regimes. A real process
  from a foreign directory emits parseable JSON and rejects unknown formats.
- A three-run byte pattern exercises FastLZ's immediate consecutive match path;
  renaming byte symbols preserves the compressed length. No production source
  changed, and no estimate is presented as a current network price.
- All 31 L2 tests pass in 4.18 seconds. Coverage is 229/229 statements and 56/56
  branches, without exclusions (`l2-coverage137.json`). Combining with checkpoint
  136's unchanged-source evidence gives 446/1045 operational statements and
  97/238 branches (`scripts-combined137.json`). This is an incremental aggregate,
  not a new full-suite execution.
- Added and locally passed an exact 100% regression gate for the completed HPKE
  and L2 scripts (244 statements, 58 branches). The all-script report still
  exposes remaining gaps. Ruff, whitespace and workflow parsing pass. Remaining
  operational behavior and browser/deployment/remote review requirements keep
  the full repository goal active.

## One hundred and thirty-eighth checkpoint

- Added actual full Poseidon parameter regeneration into a new temporary nested
  directory, comparing every generated constant and matrix to the committed
  reference. No committed constants or proving material are changed.
- Controlled only the rare matrix draws while retaining actual Grain-generated
  round constants. Duplicate draws and zero denominators each force a complete
  redraw; the accepted matrix satisfies every reciprocal identity and has a
  nonzero determinant. The round constants still match the reference.
- Verification tests cover success, one altered constant, missing files and
  malformed JSON. Verification does not rewrite its reference, including byte
  contents and modification time. Cached generation is used only for these
  filesystem/reporting tests; actual generation and live hash parity run too.
- The generator/reference-vector selection passes 18 tests in 37.23 seconds;
  the two additional malformed/missing-file cases pass in 0.06 seconds. Generator
  coverage is 77/77 statements and 20/20 branches without exclusions
  (`poseidon-generator138.log`/`.json`).
- Incremental unchanged-source aggregate: 453/1045 operational statements and
  102/238 branches (`scripts-combined138.json`). Extended the completed-script
  gate to include the generator; all 321 statements and 78 branches across its
  three named scripts pass the exact 100% gate locally. Added the test file to
  operational CI. Ruff, whitespace and workflow parsing pass.
- Remaining scripts, broader browser/deployment verification and remote
  CI/review/merge evidence still prevent completion of the full repository goal.

## One hundred and thirty-ninth checkpoint

- Added isolated historical BLS input conversion tests. All recomputed fields
  match the committed benchmark vector, and the original input is unchanged.
  A temporary script symlink and dependency layout exercise both the executable
  entry and a fresh Python subprocess from a foreign working directory. Generated
  output is confined to the temporary fixture tree.
- Each BN254 reference check rejects its independently corrupted root,
  commitment or nullifier before writing output. Adding the BN254 modulus to a
  right-path element preserves the BN254 self-check but changes BLS arithmetic;
  the real BLS left/right-root consistency check rejects the conversion.
- Optimized BN254 hashes match native Python across arities 1, 2, 5 and 16,
  including modulus-equivalent inputs. No production source or committed vector
  changed. The historical BLS benchmark still uses its documented non-standard
  Poseidon variant; test parity does not approve it for production.
- All 13 tests pass in 1.62 seconds. Converter coverage is 87/87 statements and
  14/14 branches (`bls-input139.log`/`.json`). Incremental unchanged-source script
  aggregate is 540/1045 statements and 116/238 branches
  (`scripts-combined139.json`).
- Added the converter to operational CI and its completed-script gate. The
  four-script gate passes locally with 408/408 statements and 92/92 branches.
  Ruff and whitespace pass. Remaining operational, browser/deployment and remote
  CI/review/merge requirements keep the original goal active.

## One hundred and fortieth checkpoint

- Added synthetic HTTPX transport tests for all three sanctions source fetchers:
  XML namespaces, crypto features, ordinary/empty IDs, raw tokens, CSV/EU text,
  duplicate counts, digest/length/Last-Modified metadata, malformed XML, HTTP
  errors and read timeouts. Address token tests reject names and malformed hex.
  No request reaches a live sanctions endpoint.
- Isolated builder lifecycle tests cover synthetic online and offline modes,
  duplicate normalization, depth extension, output provenance and real native
  Poseidon roots. The existing leaf-vector verifier detects missing/altered
  vectors and does not rewrite files. Its executable verify entry runs against
  a temporary symlinked checkout. All output paths are temporary; no deployed
  root, source logic or build-script version is changed.
- All 33 selected tests pass in 3.62 seconds. Builder coverage is 293/293
  statements and 70/70 branches without exclusions
  (`sanctions-sources140.log`/`.json`). This proves source execution, not a claim
  that `--verify` audits fetched-source provenance or the entire stored tree;
  its actual leaf-vector scope is recorded in the operational inventory.
- Incremental unchanged-source aggregate is 731/1045 statements and 165/238
  branches (`scripts-combined140.json`). Added these tests to operational CI;
  the completed five-script gate passes locally at 701/701 statements and
  162/162 branches. Ruff, whitespace, YAML parsing and REUSE pass.
- Orchestration runners, JavaScript/shell verification, broader browser/deployment
  checks and remote CI/review/merge remain unfinished. The full goal stays active.

## One hundred and forty-first checkpoint

- Instrumented the pilot contract-fixture generator using actual inspected
  development artifacts and fresh Groth16 proofs. Successful JSON identifies
  synthetic/unapproved scope, the requested registry/time, eight checkpoint heads
  and proof expiry. Altering the public authorization nullifier after real proof
  generation makes actual pairing verification reject the fixture without JSON.
- Both proof paths remove their owned temporary files. Separate injected prover
  timeout and nonzero-exit tests verify exception propagation, no fixture JSON
  and removal of the already-written witness input.
- The real-proof pair passes in 9.75 seconds; the two process-failure cases pass
  in 0.77 seconds. Runner coverage is 48/48 statements and 8/8 branches, with
  no exclusions (`contract-fixture141.log`/`.json`). The exact 100% runner gate
  passes locally. No application source or proving material is changed.
- Added an explicit artifact-backed CI check after fresh proof setup. Its raw
  script coverage and JSON use the retained Python evidence path, while the
  existing three-file application aggregate remains scoped to its own runs.
  This prevents the operational job from claiming a pass through missing-artifact
  skips. Incremental operational coverage is 779/1045 statements and 173/238
  branches (`scripts-combined141.json`).
- Ruff and whitespace pass. Remaining orchestration scripts, JavaScript/shell
  coverage, browser/deployment audit and remote CI/review/merge keep the full
  repository goal open.

## One hundred and forty-sixth checkpoint

- Established a root Vitest/V8 script suite with explicit dependencies and all
  four JS/MJS files in the inventory, including unimported generators. Python
  subprocess acceptance remains separate from JavaScript instrumentation.
- New EIP-2537 probe tests exposed false positives: generic JSON-RPC errors and
  unexpected returns could produce an all-chains-success summary; failed fetches
  leaked abort timers. Five of the initial six checks failed on the original.
- Changed the probe to one valid infinity pair (384 zero bytes) and require the
  exact 32-byte true result. HTTP/JSON-RPC errors are unconfirmed and use fallback
  endpoints; unexpected data counts as unconfirmed. Timers clear in finally,
  including aborted requests. The vector follows EIP-2537 and also returned the
  expected result through the actual local Hardhat precompile. No live endpoint
  was queried and no current public-network availability claim is made.
- All eight tests pass. Probe coverage is 32/32 statements, 16/16 branches,
  28/28 lines and 1/1 functions (`scripts-js146.log`, preserved summary JSON).
  Running only the happy-path test fails all four per-file gates as expected
  (`scripts-negative146.log`). The all-script aggregate remains 32/117 statements,
  16/40 branches, 28/105 lines and 1/11 functions until the other scripts execute.
- Added CI execution/report retention and documented commands. Workflow YAML and
  whitespace pass. Remaining JS generators/helper, shell checks, full aggregate
  refresh, browser/deployment audit and remote CI/review/merge keep the goal open.

## One hundred and forty-seventh checkpoint

- Added verifier generator tests against the committed BN254 and BLS benchmark
  keys: exact contract text parity, fresh Node CLI processes from foreign working
  directories, missing arguments, unsupported protocol/curve, inconsistent public
  input counts and malformed JSON without overwriting an existing output.
- After correcting two test-harness assumptions, two real regressions remained:
  the BN254 template emitted an older string-revert interface instead of the
  committed PublicSignalExceedsScalarField error, and the BLS generator ignored
  inconsistent nPublic metadata. Updated the template and added the BLS metadata
  check. Generated valid output now matches both committed contracts exactly;
  no committed key or contract changed.
- All 24 JavaScript script tests pass. BN254 generator coverage is 28 statements,
  10 branches, 26 lines and four functions; BLS is 41 statements, 12 branches,
  35 lines and four functions, all 100% (`verifier-generators147.log` and preserved
  summary). Their wildcard gate fails when only output-parity tests run, proving
  it requires rejection paths (`verifier-negative147.log`).
- Real fresh legacy/pilot and committed BLS contract checks pass all ten tests
  without skips in seven seconds (`verifier-real147.log`). Normal bindings and
  production contracts remain unchanged. This verifies existing benchmark/code
  behavior, not production approval of development proving artifacts.
- JS aggregate is now 101/120 statements, 38/42 branches, 89/108 lines and 9/11
  functions. Only the Poseidon helper remains unmeasured in V8. Whitespace and
  REUSE pass. Shell tests, complete evidence refresh/CI aggregation, browser and
  deployment audit, and remote CI/review/merge still keep the full goal active.

## One hundred and forty-second checkpoint

- Added controlled subprocess/HTTP boundary tests for checkpoint orchestration:
  workspace CLI resolution, compilation before node creation, loopback RPC scoped
  to the pytest child, preserved parent environment, propagated child exit status,
  compile/startup/test-launch failures, transient readiness retries, deadline and
  wrong-chain rejection. Cleanup targets only the owned process group and
  escalates from SIGTERM to SIGKILL after its grace period.
- All 11 orchestration tests pass in 0.40 seconds; coverage is 44/44 statements
  and 6/6 branches, without exclusions (`checkpoint-runner142.log`/`.json`).
  Separately reran the actual owned Hardhat EVM integration: one passed, two
  warnings, 0.82 seconds of pytest time (`checkpoint-real142.log`), runner exit 0.
  The controlled failure tests do not substitute for that real success path.
- Added the runner tests to operational CI and extended its completed-script
  gate. The six-script gate passes locally at 745/745 statements and 168/168
  branches; the contract-fixture gate remains in the fresh-artifact job.
  Incremental unchanged-source aggregate is 823/1045 statements and 179/238
  branches (`scripts-combined142.json`). No production source changed.
- Ruff, whitespace and workflow parsing pass. The development, local-pilot and
  mirror runners remain partially/unmeasured, alongside JavaScript/shell checks,
  broader browser/deployment audit and remote CI/review/merge. Goal remains open.

## One hundred and forty-third checkpoint

- Added local-pilot orchestration tests for required executable permissions,
  missing artifacts, PostgreSQL version, existing output refusal, private socket
  length, TCP rejection, child-only database environment, failed start/create/test
  commands and stop failures with/without a remaining PID file. All 17 tests pass
  in 1.46 seconds; runner coverage is 43/43 statements and 8/8 branches
  (`pilot-local143.log`/`.json`).
- Ran the actual local-pilot command with PostgreSQL 18 and existing unapproved
  development artifacts. Its full mirror acceptance passes 223 tests, no skips,
  six warnings in 149.78 seconds, and the parent exits 0
  (`pilot-local-real143.log`). Verified the private output directory, all nine
  retained report hashes and cluster shutdown (`pg_ctl: no server running`).
  Complete output stays private at the external `pilot-local-real143` directory.
- While that run executed, added 14 separate mirror doctor/report checks. Doctor
  results must accept only the pinned development profile and reject production
  use; incorrect statuses, pins, support flags, exit codes, stderr or assurance
  are rejected. Retained reports require the exact inventory, valid JSON and
  separate reviewer key; manifests hash every report, use mode 0600 and refuse
  overwrite. All 14 pass in 0.38 seconds (`mirror-reports143.log`/`.json`).
- Mirror script coverage is now 47/105 statements and 17/38 branches; main
  startup/readiness/cleanup remains uncovered. Incremental all-script coverage is
  913/1045 statements and 204/238 branches (`scripts-combined143.json`). No
  operational production source changed.
- Added both test modules to operational CI and the local runner to its completed
  script gate, which passes locally at 788 statements and 176 branches. Ruff,
  REUSE, whitespace and YAML parsing pass. Development/mirror orchestration,
  JavaScript/shell coverage, browser/deployment audit and remote CI/review/merge
  still keep the full repository goal open.

## One hundred and forty-fourth checkpoint

- Added mirror orchestration tests for explicit database/bundle requirements,
  doctor rejection, existing output refusal, optional private output permissions,
  child-only loopback RPC/artifact/policy settings and removal of inherited
  capture destinations. Parent environment remains unchanged.
- Covered readiness retry/deadline/wrong-chain/node-exit paths, child launch and
  execution timeouts, failed exit status, report-finalization errors and already
  exited process groups. Cleanup kills/reaps both owned processes and closes
  its private EVM log; unsuccessful tests do not publish a success manifest.
- All 31 orchestration/report checks pass in 0.62 seconds. Mirror script coverage
  is 105/105 statements and 38/38 branches without exclusions
  (`mirror-runner144.log`/`.json`). Production source is unchanged, so checkpoint
  143's actual 223-test PostgreSQL/EVM acceptance remains current evidence.
- Added this test module and the mirror script to the operational CI gate.
  Eight gated scripts pass locally with 893/893 statements and 214/214 branches;
  the artifact-dependent contract fixture retains its separate gate. Incremental
  all-script coverage is 971/1045 statements and 225/238 branches
  (`scripts-combined144.json`).
- Ruff, whitespace and YAML parsing pass. The development setup runner is the
  only Python script with remaining missed lines/branches. JavaScript/shell
  measurement, browser/deployment audit and remote CI/review/merge also remain;
  the full repository goal is not complete.

## One hundred and forty-fifth checkpoint

- Added development setup precondition tests for missing tools/dependencies and
  existing directories/symlinks. A dangling symlink exposed a real overwrite-guard
  defect: resolving the destination first created the symlink target. Changed the
  destination to an absolute, unresolved path so exclusive mkdir rejects the
  symlink itself. The regression failed before the one-line fix and passes after.
- Controlled phase-one orchestration covers both prepared-file copying and fresh
  contribution/preparation ordering, explicit unapproved labels, SHA-256 output
  and removal of intermediates, stopping at the compiler boundary. The separate
  real subprocess lifecycle tests remain active. All ten tests pass in 2.20 seconds
  (`development-unit145.log`/`.json`).
- Ran the actual compiler/prover workflow under coverage with an existing local
  unapproved prepared phase-one file and new external output. After the path fix,
  reran the complete workflow into `development-coverage145-fixed`: four Python
  integration tests pass in 23.87 seconds, all 32 contract tests pass in 15 seconds,
  and the runner exits 0 (`development-current145.log`). No generated proving
  material is committed; normal workspace outputs/bindings remain unchanged.
- Combined exactly the current real run's three subprocess coverage files, then
  its current unit evidence. The development runner passes 104/104 statements and
  16/16 branches. The local all-script aggregate now passes 1045/1045 statements
  and 238/238 branches across all ten Python scripts without exclusions
  (`scripts-combined145.json`). Older unchanged-script evidence is incremental;
  this is not a fresh full-repository suite execution.
- CI now measures its actual development workflow, combines its own subprocess
  data and failure-path tests, and gates the runner at exactly 100%. The same
  combination/gate passes locally. Evidence uses the existing retained Python
  artifact paths. Ruff, REUSE, whitespace and YAML parsing pass.
- Cross-job/full-suite refresh, JavaScript/shell script measurement, broader
  browser/deployment checks and remote CI/review/merge still keep the complete
  repository goal open.


### Checkpoint 148 — complete operational JavaScript coverage

- Added 11 V8-measured Poseidon helper tests using the actual circomlib implementation:
  chunked array/wrapped input, a known hash vector, malformed JSON/shapes, invalid
  integers and unsupported arities. Standard streams and exit are controlled;
  invalid-input handling explicitly returns after requesting process exit.
- All 35 operational JavaScript tests pass. All four files now pass per-file 100%
  gates: 120 statements, 42 branches, 108 lines and 11 functions in total
  (`poseidon-gate148.log`, preserved `poseidon-summary148.json`).
- A success-only negative run exits 1 and fails the helper's branch, statement,
  line and function thresholds (`poseidon-negative148.log`); error paths are
  required by the gate.
- All 12 real helper subprocess tests pass in 10.97 seconds, including large
  decimal input parity with Python from a foreign directory and actual exit
  behavior (`poseidon-real148.log`).
- Shell acceptance coverage, cross-job aggregation, fresh full-suite verification
  and remote CI/review/merge remain outstanding. No full-goal completion claim.


### Checkpoint 149 — circuit lint shell acceptance and failure propagation

- Added ten tests that execute the actual Bash script in an isolated project
  with controlled analyzer processes and a minimal command PATH. They verify
  every configured circuit, both report modes, documented and unexpected findings,
  unavailable/crashed tools and temporary-file cleanup. Four initially failed
  because analyzer failures were suppressed (`shell-lint-before149.log`).
- Fixed the runner to retain per-invocation exit status. Exit 1 with diagnostics
  still reaches normal allowlist filtering; other failed invocations produce an
  unexpected error, including fatal failures with an otherwise allowed warning.
- All ten tests pass in 7.99 seconds (`shell-lint149.log`). Actual Circomspect
  passes with five documented findings and zero unexpected findings
  (`shell-lint-real149.log`). A separate real SARIF run produces seven valid
  SARIF 2.1.0 reports in external `lint-sarif149-icsng8mo`; no generated report
  or circuit artifact is added to the worktree.
- CI operational tests now include these regressions. Ruff, Bash syntax,
  whitespace and CI YAML parsing pass. Shell coverage is behavioral evidence,
  not an instrumented percentage. Protobuf/build-script acceptance, aggregate
  coverage verification and remote CI/review/merge remain outstanding.


### Checkpoint 150 — protobuf shell regeneration acceptance

- Added 17 actual Bash entry-point tests in private project copies. Real pinned
  grpcio-tools regeneration reproduces all four committed stubs byte-for-byte;
  check mode leaves bytes and modification times unchanged. Every stale and
  missing output is individually detected without publishing files.
- Controlled compiler-format fixtures exercise both warnings-import variants,
  all five required postprocessing patterns, and compiler exit failure. Failures
  retain existing stubs and clean temporary generation directories. Generated
  repository files and the regeneration script are unchanged.
- All 17 tests pass in 8.33 seconds (`protobuf-shell150.log`); Ruff and whitespace
  checks pass. CI operational acceptance now includes this test file. This is
  shell behavior evidence, not an instrumented shell coverage percentage.
- Build-shell acceptance and aggregate/full-suite/remote verification remain.


### Checkpoint 151 — build shell acceptance and atomic phase-one download

- Added 26 Bash acceptance tests with synthetic tools/artifacts: downloaded,
  cached and local phase-one paths; unavailable prerequisites; bad checksums;
  failed-download retry; six missing outputs; GNU/BSD/unavailable file sizes;
  nine stage failures; explicit and generated development entropy. No public
  network or ceremony is invoked by these control-flow tests.
- One initial failure exposed a partial-download cache bug: curl failure left
  the final ptau filename, so a later run bypassed downloading/checksum checks.
  Downloads now use a temporary file, cleanup trap and a rename only after
  checksum verification. All 26 tests pass in 26.13 seconds
  (`compile-shell151.log`; initial failure in `compile-shell-before151.log`).
- Executed the current actual build script in external `compile-real151-6rox58uf`
  using the existing explicitly unapproved local phase-one material. Real Circom
  compilation, Groth16 setup/contribution, verification-key export and Solidity
  generation all pass. The key has 16 public signals and 17 IC points; temporary
  zkey cleanup passes (`compile-real151.log`, `compile-real151-result.json`).
- The real CLI demo generates and verifies a proof using these fresh artifacts
  (`compile-proof151.log`). An initial direct snarkjs attempt used the SDK's
  camelCase input vector and was rejected for signal naming; the supported CLI
  performs the required mapping and passes. No circuit/artifact changes were
  needed, and no production setup approval is implied. Artifacts remain external.
- CI includes build-shell acceptance. Ruff, Bash syntax, whitespace and CI YAML
  parsing pass. These three shell scripts now have explicit acceptance evidence;
  this is not an instrumented Bash coverage percentage. Final aggregate/source
  refresh and remote CI/review/merge remain incomplete.


### Checkpoint 152 — cross-job Python aggregate gate

- Operational CI now uses a named coverage data file and retains raw data beside
  JSON. Added a dependent aggregate job that downloads both named artifacts and
  combines exactly application-combined, operational, development-combined and
  contract-fixture data. The final report includes both `src` and every Python
  operational script, with a 100% gate and retained combined data/JSON.
- Executed the current operational CI test command locally: 234 pass in 210.90
  seconds (`operational152.log`, `.data`, `.json`). Separately refreshed all four
  real contract-fixture tests: four pass in 14.70 seconds and the script remains
  48/48 statements and 8/8 branches (`contract-fixture152.*`).
- Recreated the exact artifact-download layout externally and executed the YAML
  aggregate command. It passes 9377/9377 statements and 2306/2306 branches across
  all 153 Python files (`aggregate152.log`, `aggregate152/repository-python-coverage.*`).
  The existing excluded line remains unchanged. No report includes fewer files
  to obtain the result.
- Removing the contract-fixture input produces a failing gate with a missing
  statement and two partial branches (`aggregate-negative152.log`), confirming
  the dedicated artifact-backed evidence matters. CI YAML and whitespace checks
  pass. Application/development inputs still use their earlier unchanged-source
  runs; full fresh-suite and remote execution/review/merge remain outstanding.


### Checkpoint 153 — refresh started; contract TypeScript inventory gap

- Started a fresh full Python suite with a newly owned private PostgreSQL 18
  cluster, both current development proof bundles and explicit CLI acceptance.
  The same runner will execute checkpoint and mirror coverage separately and
  stop its owned cluster in a finally block. At this checkpoint the suite is
  still running; `python153-run.json` and `python-suite153.log` are live evidence,
  not a passing result. Keep following this run rather than restarting it.
- Refreshed content, CLI, SDK, docs and root operational JavaScript coverage;
  all five existing gates pass (`*-coverage153.log`, preserved summary JSON).
- The deployment audit identified twelve authored contract-tooling TypeScript
  files missing from V8 measurement. Added a separate report that includes all
  twelve files. Eleven tests cover configured network selection/RPC overrides
  and verifier preparation, including invalid delays and pending activation.
  Both helper files pass 100% gates; the overall report remains partial at
  16/643 statements, 11/180 branches, 14/632 lines and 4/49 functions
  (`contract-scripts153.log`, `contract-scripts153-summary.json`).
- Both actual Hardhat deployment-preparation tests pass in 11 seconds
  (`deployment-real153.log`), including both entry points and pending activation
  records. All activity is local; no live deployments/root updates occur.
- CI now runs and retains the additional report. The other ten contract scripts
  explicitly remain unmeasured; these gaps must be closed before full repository
  coverage can be claimed. Full fresh Python completion, broader final audit and
  remote CI/review/merge remain pending.


### Checkpoint 154 — registry tools and gas benchmark coverage

- Added 30 tests for transfer lookup and proof submission: deployment-file and
  explicit configuration, default/text/bytes32 identities, recorded timestamps,
  supported proof envelopes, G2 coordinate order, exact signal count, malformed
  integers/files, missing metadata, RPC/submission/receipt rejection and nonzero
  error exits. Both scripts reach 100% on all V8 metrics without source changes.
- Added three gas benchmark tests covering successful gas reporting, unauthorized
  registration, refusal of a non-ephemeral network and deployment failure. The
  actual `hardhat run scripts/gas-bench.ts --network hardhat --no-compile` command
  also passes (`gas-real154.log`) using normal bytecode.
- All 44 contract-script tests pass with five per-file 100% gates
  (`contract-scripts-gate154.log`, `contract-scripts154-summary.json`). The initial
  two-default-flow-only run fails the registry thresholds, confirming success
  paths alone cannot satisfy the gates (`registry-negative154.log`).
- Overall contract-script coverage remains partial: 118/643 statements, 59/180
  branches, 115/632 lines and 16/49 functions. Seven additional scripts still
  require measurement. No public transactions or root updates were performed.
- The existing full Python process remains live and progressing; do not replace
  its still-running evidence with an earlier aggregate or restart it. Full
  verification and remote CI/review/merge remain unfinished.


### Checkpoint 155 — relay deployment and fresh Python suite result

- Added eleven relay-deployment boundary tests. All 55 contract-script tests
  pass with six 100% per-file gates (`contract-scripts-gate155.log`, preserved
  `contract-scripts155-summary.json`). The relay script covers all 45 statements,
  ten branches, 45 lines and two functions without changing production source.
- Added an actual Hardhat entry-point test using a temporary script/record tree
  and ephemeral EVM. It confirms deployed relay bytecode, granted oracle role,
  preserved oracle address/metadata and a timestamp. The test passes in four
  seconds (`relay-real155.log`); contract TypeScript noEmit checking passes
  (`relay-typecheck155.log`). All deployment activity remains local.
- The fresh full Python suite finishes successfully: 2502 passed, one skipped,
  42 warnings in 684.33 seconds (`python-suite153.log`/`.json`/`.data`). It covers
  8332/8332 statements and 2068/2068 branches. The sole skipped checkpoint test
  then passes on its owned EVM (one passed, two warnings, 2.77 seconds in
  `python-checkpoint153.log`). The mirror stage then passes all 223 tests with
  six warnings in 274.43 seconds (`python-mirror153.log`). The runner exits 0,
  removes its owned PostgreSQL process, and a separate pg_ctl status check
  confirms no server is running.
- Combined the fresh suite/checkpoint/mirror data: 8332/8332 statements and
  2068/2068 branches pass (`python-combined155.*`). Combining that with the current
  operational, development and fixture evidence again passes 9377/9377 statements
  and 2306/2306 branches across 153 files (`repository-combined155.*`). Development
  evidence is still from the earlier unchanged-source real build; this is not a
  newly executed ceremony or remote CI run.
- Six contract scripts, the broader final audit and remote CI/review/merge remain
  unfinished. Full Python application coverage does not close those wider gaps.


### Checkpoint 156 — both main deployment entrypoints fully measured

- Added 29 contract-script tests for deployment configuration, canonical
  constructor/override thresholds, case-normalized jurisdiction keys, record
  persistence after transaction confirmation, pending activation metadata, role
  assignment, empty balance, and failures during deployment/seeding/confirmation/
  persistence. Explorer tests cover local-network suppression, both API-key
  selections, successful constructor verification and both error-message forms.
- Both unchanged deployment entrypoints now pass per-file 100% V8 gates:
  deploy.ts has 66 statements, nine branches, 65 lines and four functions;
  deploy-multichain.ts has 84 statements, twelve branches, 83 lines and four
  functions (`deploy-main-gate156.log`, `contract-scripts156-summary.json`).
- All 84 contract-script tests pass. The broader report remains partial at
  313/643 statements, 90/180 branches, 308/632 lines and 26/49 functions.
  The four remaining scripts are BLS deployment, verifier replacement, root
  update and root relay. No production source or generated artifacts changed.
- The existing two real local deployment-preparation tests remain applicable
  unchanged-source evidence (`deployment-real153.log`); no public deployment or
  oracle update was performed. Whitespace checks pass. Final Solidity/browser
  refresh, remaining script coverage and remote CI/review/merge remain open.


### Checkpoint 157 — BLS deployment measurement and accurate network reporting

- Added twelve BLS entry-point tests for field encoding, valid/tampered proof
  results, missing vector files, zero balance, optional deployment receipt,
  deployment/estimate/write failures and actual chain-ID reporting. Explicit
  returns after exit requests make termination boundaries clear.
- Fixed unconditional Sepolia-task completion output: successful runs only
  claim Sepolia confirmation for chain 11155111. An environment network label
  alone does not satisfy that check; local runs retain an explicit separate-task
  message. Development-only benchmark notes remain in the deployment record.
- All 96 contract-script tests pass, with nine per-file 100% gates. BLS coverage
  is 57 statements, 15 branches, 57 lines and four functions, all covered
  (`contract-scripts-gate157.log`, `contract-scripts157-summary.json`).
- A real copied entrypoint deploys on the ephemeral Hardhat network, accepts the
  committed BLS proof, rejects its tampered variant and records positive gas
  measurements without claiming Sepolia confirmation. It passes in three seconds
  (`bls-real157.log`); contract TypeScript checking and whitespace checks pass.
  No public deployment or generated proving material is published.
- Inspection of verifier replacement found immediate activation after router
  registration despite the router's nonzero timelock, plus a previous-address
  field populated with the new address. These need targeted regression tests and
  correction next. Overall tooling measurement remains 370/645 statements,
  105/182 branches, 365/634 lines and 30/49 functions. Replacement, root update,
  root relay, final layer refresh and remote verification remain unfinished.


### Checkpoint 158 — resumable verifier replacement and real timelock regression

- Added a real-router entrypoint regression. Running it against the previous
  script fails at immediate activation with `Unauthorized`
  (`replacement-before158.log`). The corrected script records a pending verifier,
  reads the actual timelock and chain timestamp, and permits a later invocation
  to activate/select that same verifier. An early repeat sends no transaction.
- The workflow validates chain, router/registry binding, pending scope and
  selector consistency. It rejects conflicting pending registrations and disabled
  replacements. Current on-chain state allows retries after registration failure,
  activation, selector change or final record-publication failure. Atomic file
  publication protects the preceding JSON record; rollback history now retains
  the original verifier and selector. Removed obsolete unused threshold parsing
  and jurisdiction encoding, since this script preserves the existing registry.
- Added 22 boundary/retry tests. All 118 contract-script tests pass with ten
  per-file gates (`contract-scripts-gate158.log`, `contract-scripts158-summary.json`).
  Replacement covers 71/71 statements, 48/48 branches, 67/67 lines and 3/3 functions.
- The final real entrypoint test passes in four seconds: pending state, unchanged
  early-retry nonce, expiry-bound activation, original stateful addresses and
  correct rollback metadata (`replacement-real158.log`). The test advances only
  its own ephemeral EVM clock; the actual script contains no clock manipulation.
  Contract TypeScript checking and whitespace checks pass. Resume behavior is
  documented in packages/contracts/README.md. No live deployment was changed.
- Two sanctions scripts, final layer refresh and remote CI/review/merge remain.
  Overall contract-tooling measurement is still partial at 441/647 statements,
  153/220 branches, 432/633 lines and 33/49 functions.
