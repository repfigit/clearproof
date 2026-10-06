# Current-profile native proving comparison

Date: October 5, 2026. Profile: `pilot-transfer-v3`, eight public signals,
95,408 constraints and 95,450 wires. Inputs and artifacts are wholly synthetic,
with unapproved development keys. [Raw samples and provenance](2026-10-05-native-prover.json)
retain every observation and exact binary/key/witness/R1CS SHA256.

## Result and backend decision

| Proving implementation | Median wall time | Range, five measured runs | Median peak process RSS |
| --- | ---: | ---: | ---: |
| snarkjs CLI, default workers | 4.91 s | 4.59–5.20 s | 2,595.3 MiB |
| rapidsnark, `OMP_NUM_THREADS=1` | 1.05 s | 1.03–1.30 s | 86.1 MiB |
| rapidsnark, `OMP_NUM_THREADS=4` | 1.05 s | 0.91–1.14 s | 85.7 MiB |

The native proving phase was 4.7 times faster than the snarkjs CLI median on this
host, with substantially lower process RSS. That supports an optional pinned
native backend while retaining JavaScript fallback. It does not support the
original issue's proposed universal 10–30-fold improvement or 100–200 ms latency.

All 18 warmup/measured proofs independently paired in snarkjs and matched the
same eight expected public signals. A changed public signal was independently
rejected for each implementation. Randomized proof coordinates need not match.

## Method and limits

One warmup and five measured invocations per implementation used the same
43,818,966-byte proving key and 3,054,476-byte WTNS. `/usr/bin/time` measured wall,
user/system CPU and maximum RSS. Timings include process startup, key/witness
reads and proof/public output writes. They exclude witness construction,
independent pairing and queue/service overhead. GNU time's process RSS is not a
measurement of aggregate container memory or anonymous shared-memory charge.

Both implementations used CPU affinity `[0, 1, 2, 3]`, four distinct physical
cores, on an AMD Ryzen AI 9 HX 470 host with 24 logical CPUs. snarkjs selected
24 workers from `os.cpus().length`; upstream native FFT/MSM pools selected
`std::thread::hardware_concurrency()`. OpenMP settings restrict OpenMP regions,
not those native pools. The affinity bounds CPU capacity for both implementations.
Five observations support this local comparison; they do not establish a
production percentile, steady-state concurrency limit or deployment throughput.

The native runtime was upstream rapidsnark
`81eddf1a536d26497b237c0b8a04fe90baf7e439`, compiled using GCC 15.2 and NASM 3.01,
static GMP 6.3.0, Release mode and an incidental-header compatibility include.
Arithmetic sources were unchanged. Its SHA256 was
`f2938dd7fb064365fa522d1c38551232b7122417d216ba449f940de827fd6263`.
The R1CS SHA256 was
`4248cc7b67e7ead5a4ac7a4425acd0debffaee9642d540846be58daeae551aa8`.

This is the current eight-signal profile. The July fflonk/Groth16 report measured
a different, 30,164-constraint legacy circuit with 16 signals; its figures cannot
be combined with this comparison to derive a deployment ratio.

## Reproduce

Install the repository's locked development dependencies and generate an isolated
synthetic bundle with `scripts/test_development_circuits.py`; see
[local acceptance](../operations/local-pilot-acceptance.md). Build a native
development executable with the
[source-pinned recipe](../operations/pilot-native-proving.md). Then run:

```bash
uv run --no-sync python docs/benchmarks/native_prover.py \
  --artifacts /tmp/development-circuits/pilot \
  --native /tmp/clearproof-native-build/build_prover/src/prover \
  --native-sha256 <development-binary-sha256> \
  --output /tmp/new-native-benchmark
```

The output directory must be new. The harness requires an explicit unapproved
current-profile bundle, the binary pin, GNU time, `taskset` and `lscpu`. It pairs
every generated proof, rejects a changed public statement and writes all samples
and a summary. `--cores` selects one through four distinct permitted physical
cores; `--samples` selects one through twenty measured runs plus a warmup.
Use only the generated synthetic bundle. The prove-only harness deliberately uses
synthetic WTNS/proof files; the [worker backend](../operations/pilot-native-proving.md)
uses anonymous memory for private intermediates and pairs before retaining any
result. Proving-phase figures exclude its Node witness/verification phases.
