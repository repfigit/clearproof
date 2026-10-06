# Optional native pilot proving

The durable `pilot-transfer-v3` worker can use an operator-pinned rapidsnark
executable on Linux. JavaScript remains the default. The native executable proves
the same eight-signal statement; the independently pinned snarkjs runtime pairs
the result before completion. Current enrollment, policy, roots, time and
authorization checks remain those of the [job service](pilot-proving-jobs.md).

## Select in the operator factory

After loading the existing pinned `PilotProver`, choose a backend explicitly in
the shared API/worker target factory:

```python
from src.prover.pilot_native_prover import select_pilot_backend
from src.services.proof_jobs import ProvingTarget

selected = select_pilot_backend(javascript_prover)
target = ProvingTarget(configuration, selected, sanctions_tree)
```

Set `CLEARPROOF_RAPIDSNARK_BIN` to an operator-owned executable path and
`CLEARPROOF_RAPIDSNARK_SHA256` to independently approved bytes. Alternatively,
provide the SHA256 and discover `rapidsnark` or `prover` in `PATH`. Automatic
discovery without a binary or approved pin preserves JavaScript. An explicit bad
path/pin fails closed; an invalid native proof never triggers fallback. The
helper preserves the supplied JavaScript implementation outside Linux. The
durable job worker still requires Linux; existing JavaScript SDK/CLI paths keep
their platform behavior.

Binary bytes are checked at load and snapshotted/rechecked for every operation.
The native binary and pairing-runtime fingerprints enter the retained target
digest. API and worker must select the same backend bytes. CPU placement and
heap limits can differ across replicas without changing the statement digest.
The file path never comes from a request, and API responses expose no paths.

## Source-pinned development build

The supplied recipe requires Linux x86_64, GCC/G++, make, CMake, NASM, m4, git,
curl, Python 3 and `realpath`. It installs no system packages and writes into a
new directory outside the repository:

```bash
bash scripts/build_native_prover.sh /tmp/clearproof-native-build
```

It checks out upstream rapidsnark at
`81eddf1a536d26497b237c0b8a04fe90baf7e439`, verifies its two needed submodule
revisions, builds SHA-pinned GMP 6.3.0 and retains the source/license notices.
The receipt records the actual binary SHA256, compiler and assembler. GCC 15
compatibility uses GNU17 for GMP configure tests and a forced `cstdint` include;
the arithmetic sources are unchanged. Compiler, CPU and build paths can change
the binary hash; this is a source-pinned recipe, not a byte-reproducibility claim.
The generated receipt is development provenance, not operator approval.

Upstream documents LGPL-3.0 licensing in its
[repository](https://github.com/iden3/rapidsnark/tree/81eddf1a536d26497b237c0b8a04fe90baf7e439).
The recipe retains upstream dependency notices and source. No native binaries or
new compiled proving keys are bundled with Clearproof; distribution of a native
runtime requires the corresponding license/source arrangements.

## Private transport and resource bounds

The worker calculates WTNS using the pinned WASM in Node, writes it to an
anonymous Linux memory file, proves with sealed snapshots of the native
executable/key/witness, and verifies the proof in a guarded Node subprocess.
Witness and proof/public intermediates have no on-disk files. Arguments
contain only public configuration and inherited `/proc/self/fd` references;
private input enters through stdin. Temporary files contain public runtime code.
The holder secret, witness and generated proof are never written to disk.

Each phase disables core dumps, sets parent-death SIGKILL, uses a new owned
process group, restricts CPU affinity to one through four permitted CPUs and
limits file growth to 4 MiB. A shared 1–120 second operation timeout covers all
phases; cancellation kills and reaps the current child before returning. Binary
snapshots are bounded to 64 MiB, key/WASM snapshots to 128 MiB, WTNS to 4 MiB,
proof JSON to 8 KiB and public JSON to 2 KiB. The current synthetic WTNS is
3,054,476 bytes. Proof shape, all expected public signals and independent pairing
must pass before any result is retained.

Affinity defaults to the first four CPUs permitted to the process, or fewer if
the host permits fewer. For a different operator-owned placement, pass
`cpus=(...)` to the selector. OpenMP settings alone do not limit upstream's
`std::thread` pools. CPU affinity bounds CPU capacity; it does not limit total
thread count. Measure capacity before increasing queue concurrency.

Anonymous memory can swap. Disable sensitive-memory swapping and parent core
dumps, and enforce independent container/cgroup memory limits. The Node heap cap
does not bound RSS or shared memory. Native proving's process RSS excludes Node
witness/verification phases, the Python parent and anonymous key/witness pages;
size the complete job. Hosts must support memory-file sealing and execution of
an operator-approved memory snapshot; unsupported host policy fails closed.
SQL leases alone do not fence arbitrarily frozen or partitioned hosts.

## Verification and measurement

The [dated benchmark](../benchmarks/2026-10-05-native-prover.md) reports the
equivalent current-profile comparison and its exact scope. On that host the
native proving phase was 4.7 times faster with about 86 MiB median peak process
RSS. These measurements do not establish a 100–200 ms production latency,
aggregate job memory or a production throughput guarantee.

Native acceptance requires an explicit unapproved bundle and source-pinned test
binary; ordinary development/CI without one exercises the JavaScript fallback:

```bash
CLEARPROOF_PILOT_TEST_ARTIFACTS=/tmp/development-circuits/pilot \
CLEARPROOF_RAPIDSNARK_TEST_BIN=/tmp/clearproof-native-build/build_prover/src/prover \
CLEARPROOF_RAPIDSNARK_TEST_SHA256=<development-binary-sha256> \
uv run python -m pytest tests/integration/test_pilot_native_proving.py
```

With an owned test PostgreSQL `DATABASE_URL`, this also checks an actual durable
native job and rejects retrieval after a backend replacement. All examples use
synthetic fixtures. Production ceremony, independent audits and interoperability
gates remain open.
