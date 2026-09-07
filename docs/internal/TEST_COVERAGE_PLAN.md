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

Python: chain writer, snarkjs prover, gRPC failure paths, keyring rotation,
API startup/shutdown and proof route error paths. The current combined report
still has 927 missed lines and 467 missed branches. Subprocess coverage must also be captured before interpreting child
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
