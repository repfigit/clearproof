# Full coverage completion audit

Audited source: `23c1f30` on `test/full-coverage`. This is an incomplete completion
audit, not a release claim. PR #29 is open for review; CI run 34196562090 is in progress.
Local evidence paths below are relative to `/home/agent/.cache/clearproof-tests`.

| Requirement | Inspected evidence | Status |
| --- | --- | --- |
| All Python application and operational source measured | `repository-combined155.json`: 153 files, 9377/9377 statements, 2306/2306 branches; compared against current tracked `src/**/*.py` and `scripts/*.py`, none missing | Local evidence passes; remote aggregate pending |
| Generated protobuf retained | All generated files remain in the Python report; no changes under `protos/` or generated protobuf sources | Local evidence passes; remote freshness check passes |
| Every TS source workspace measured | `*-coverage153-summary.json` compared to tracked runtime source: content 5, CLI 18, SDK 16, docs 8 files; none missing, all metrics 100% | Local and remote workspace gate pass |
| Operational JS/TS measured separately | Root JS 4 files, 120 statements/42 branches; contract scripts 12 files, 678 statements/254 branches; all metrics 100% | Local and remote script gates pass |
| Solidity coverage and normal-bytecode real proofs | `contracts161-result.json` stages all exit 0; 138 tests each mode; raw maps 275 statements/402 branches/387 lines/88 functions, all covered | Local evidence passes; remote fresh-proof run pending |
| Actual Circom witness and proof constraints | Full Python suite with tools/artifacts has only the explicitly separate checkpoint skip; development setup and normal Solidity runs verify both proof profiles | Local evidence passes; remote fresh setup pending |
| Real persistence and external boundaries | `python-suite153.log`: 2502 pass; `python-mirror153.log`: 223 pass; `python-checkpoint153.log`: 1 pass; runner result confirms owned PostgreSQL stopped | Local evidence passes; remote full suite pending |
| Browser behavior | `docs-multibrowser161-final.log`: 76 pass across desktop/mobile Chromium, Firefox and WebKit, production MDX/navigation/Mermaid/content API paths | Local and remote browser suites pass |
| Shell entrypoints | Operational inventory records 26 compile, 10 lint and 17 protobuf acceptance cases plus actual compiler/analyzer/protobuf execution | Local and remote operational jobs pass |
| CI evidence retained and gates enforce coverage | Inspected workflow includes full Python cross-job aggregation, four workspace gates, JS/TS script gates, Solidity gate and report uploads | Configuration inspected; remote completion/artifacts pending |
| Review, clean merge and merged-main verification | https://github.com/repfigit/clearproof/pull/29 | Outstanding |

## Conditional execution inventory

The full Python run reports exactly one skip: the test in
`tests/integration/test_pilot_checkpoint.py`, which passes separately against its
owned EVM. Database-gated wallet/storage/publication tests, artifact-gated legacy
and pilot proof tests, and tool-gated Circom/Node tests therefore execute in the
full run. The combined report includes the separately executed checkpoint.

Several pilot-storage assertions conditionally execute without a pytest skip.
The mirror runner sets `CLEARPROOF_MIRROR_TEST_RPC`,
`CLEARPROOF_PILOT_TEST_ARTIFACTS` and `CLEARPROOF_POLICY_CLI_TEST=1`; its 223-test
acceptance provides the complementary execution evidence. The ordinary full
suite also enables policy CLI acceptance. These paths must remain in remote CI.

The normal contract log explicitly contains the legacy end-to-end, pilot pairing,
pilot current registry, BLS vector and L2 cost suites, with 138 passing and no
pending tests. Both artifact environment variables were provided. The L2 test's
optional-vector skip did not execute; its gas/calldata emission test passed.

Generated bindings are compiler outputs, declaration files contain no runtime
statements, and test/build configuration is exercised by the actual toolchain.
Bash and Circom have behavior/constraint evidence, not an invented line-coverage
percentage. The one pre-existing Python excluded line remains unchanged.

## Remaining audit work

Review production changes and automated review findings; inspect all remote job
results and retained full-coverage artifacts; resolve failures before making the
PR ready; merge only after clean checks; then verify merged main. No development
proving keys, public sanctions changes or public-chain transactions are part of
this work.

## Production-change review in progress

Reviewed the Solidity invariant simplifications against their earlier guards:
`validFrom <= block.timestamp < validUntil` implies the removed duration ordering
check; constructor/table updates preserve fallback threshold registration; stored
approvals are immutable and were checked against publication time. No circuit
constraint or proving artifact was changed.

Reviewed Python lifecycle cleanup, shared database transactions, idempotency
locking, audit serialization/link checks, SIWE nonce/expiry handling, prover
process ownership and temporary-file cleanup, registry depth extension, and SDK
canonical ordering/stream cleanup. Existing tests include real concurrent writes,
rollback, cancellation, credential/witness parity and rejected proofs. The audit
does not treat full line coverage alone as proof of those properties.

Reviewed operational download publication, analyzer error handling, verifier
output parity and resumable router replacement. Remote normal contract tests,
PostgreSQL storage, shell acceptance and witness gates pass. Fresh remote proof
coverage and automated review remain pending.

## Remote artifact inspection

Downloaded the `typescript-coverage` (artifact 10044134693) and
`operational-javascript-coverage` (10044127343) archives from run 34196562090.
Their SHA-256 values match GitHub's artifact metadata and both are associated
with source commit `23c1f305c606cbea4d0dfcbaac0e38ee2c02a904`. Every retained
workspace and script summary reports 100% lines/statements/functions/branches.
The reports contain content 5, CLI 18, SDK 17, docs 8, root scripts 4 and contract
scripts 12 files. The SDK report also includes its tracked declaration file,
which has no executable statements; the earlier runtime inventory counted 16.
All workspace report paths resolve to tracked files. Source application files
are unchanged since the local full Python baseline. Raw downloaded archives and
parsed summaries are retained externally as `remote-*-coverage164.zip` and
`remote-coverage164-summary.json`. Remote full Python and Solidity evidence is
still pending the active circuit job.

The final local Solidity denominator comparison also matches all 14 tracked
contract sources, including the interface, test harnesses and benchmark verifier.
Report keys are relative to the contract workspace; the comparison normalizes
that prefix before matching tracked paths.

The hosted browser job log (`remote-browser166.log`) independently confirms
76 tests started and 76 passed in 49.7 seconds. This verifies the complete
four-project matrix on the unmodified GitHub runner, without the local WebKit
shared-library workaround.

## First automated review findings

Bugbot reported two workflow concerns. The coverage-combine concern was checked
with a real parent/child coverage run using the repository configuration:
`patch = ["subprocess"]` already enables parallel mode. Combining the temporary
directory retained both files and all six executed statements. Evidence is in
`coverage-review166-oevng24b`. The workflow now passes `--parallel-mode` explicitly
to document and preserve the file-shard contract. The second finding was valid:
synthetic report and unapproved development artifact uploads now run with
`if: always()` so later coverage/test failures do not discard generated evidence.
No upload scope was broadened to include private reviewer keys or phase-one state.
