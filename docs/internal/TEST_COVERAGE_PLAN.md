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

Python: authentication middleware, route configuration errors, publication recovery,
proof preparation/projection, and historical status checks. The current combined
report has 189 missed lines and 72 missed branches after the sixty-ninth checkpoint.
Generated protobufs account for 82 missed lines and five missed branches and remain
in the denominator. Subprocess coverage is captured in this combined report.

CLI: source line/branch/function/statement coverage is now 100%, enforced by CI.
Keep the actual artifact/service acceptance tests alongside mocked boundary tests.

Solidity: router administration/timelocks, oracle updates, VASP administration,
registry validation failures and cryptographic rejection branches. Retest normal
uninstrumented bytecode as well as instrumentation; generated coverage factory
bytecode must not be committed.

These figures describe an intermediate worktree, not a released coverage claim.
The full goal remains open.

Docs: authored TS/TSX source unit coverage is now 100% and gated, as is the shared
content package. MDX rendering, browser/server behavior and operational scripts
remain part of the unfinished coverage inventory.


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
