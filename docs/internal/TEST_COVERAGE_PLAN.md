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

Python: API startup/shutdown, proof route error paths and
remaining validation branches. The current combined report
still has 632 missed lines and 410 missed branches. Subprocess coverage must also be captured before interpreting child
CLI modules as unexecuted.

CLI: source line/branch/function/statement coverage is now 100%, enforced by CI.
Keep the actual artifact/service acceptance tests alongside mocked boundary tests.

Solidity: router administration/timelocks, oracle updates, VASP administration,
registry validation failures and cryptographic rejection branches. Retest normal
uninstrumented bytecode as well as instrumentation; generated coverage factory
bytecode must not be committed.

These figures describe an intermediate worktree, not a released coverage claim.
The full goal remains open.

Docs: test routes and rendering. Browser/server behavior and operational scripts
remain part of the coverage inventory; the shared content modules now have a
100% source coverage gate.


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
