# Current-profile pairing capacity

The current pilot pairing runtime permits two active Node children per Python
process, shared across all verifier instances and event loops. Admission is
immediate: saturation raises `PairingCapacityExceeded` without creating a child
or adding a waiting queue. A slot remains occupied until its child is reaped,
including repeated cancellation during creation or cleanup. Input parsing,
statement reconstruction and database work are outside this runtime limit.

## Measured result

On October 5, 2026, the same synthetic `pilot-transfer-v3` proof, eight expected
signals, unapproved verification key and pinned snarkjs bundle were checked on
four distinct physical cores. Node was v26.5.1. One excluded warmup batch and
five measured batches per mode produced 18 accepted pairings in total.

| Active pairing processes | Median request time | Median batch throughput | Maximum sampled aggregate child RSS |
| --- | ---: | ---: | ---: |
| 1 | 0.226 s | 4.43 checks/s | 77.7 MiB |
| 2 | 0.249 s | 7.80 checks/s | 152.0 MiB |

[All samples and provenance](2026-10-05-pilot-pairing.json) retain the proof,
verification-key, manifest and runtime SHA256 values. Time includes parsing,
process startup, transport, pairing and cleanup. Linux `/proc` RSS was sampled
every 10 ms for owned Node processes, including their threads. It excludes Python,
database, proxy and container memory and can miss short peaks. It is not a hard
memory limit, a production percentile or a service throughput/SLA measurement.
The Node V8 heap cap remains 256 MiB per child; enforce separate container memory
and CPU limits. Proving has a different resource profile; use the separately
measured [native/JavaScript comparison](2026-10-05-native-prover.md).

## API and deployment behavior

Current inspection, evaluation, observation and authorization routes map pairing
saturation to HTTP 503 with `Retry-After: 1`. This response makes no decision
about proof validity. Observation/authorization transactions unwind without
publishing a new receipt; retry the same idempotency key after backoff. Durable
proof workers treat saturation as a retryable interruption, preserving their
original deadline and three-claim bound. Historical offline inspection remains
indeterminate when pairing is unavailable.

The limit is local to each Python process. Multiple API workers or replicas each
have two slots; separately supervised proving workers retain PostgreSQL's shared
proving-job limit. Do not multiply workers without accounting for that aggregate
capacity. Bound incoming HTTP connections/tasks at the server or proxy as well:
the pairing budget does not bound requests waiting on tenant locks or database
connections. For example, `uvicorn src.api.main:app --workers 1
--limit-concurrency 16 --timeout-keep-alive 5` provides a server admission ceiling;
16 is a configuration example, not a measured end-to-end capacity recommendation.

## Reproduce

Use only the explicit synthetic development bundle created by the
[local acceptance runner](../operations/local-pilot-acceptance.md), with the
repository's locked dependencies installed. From the repository root:

```bash
PYTHONPATH=. uv run --no-sync python docs/benchmarks/pilot_pairing.py \
  --artifacts /tmp/development-circuits/pilot \
  --bundle-sha256 <independently-verified-snarkjs-bundle-sha256> \
  --output /tmp/new-pairing-report.json --samples 5 --cores 4
```

The harness requires Linux `/proc`, `lscpu`, Node, an explicit current development
bundle and a new output filename. The development manifest's local pin establishes
reproducibility only. No customer information, proving key, private signer,
network access, database or authorization consumption is needed. The instrumentation
patches process creation only inside this standalone benchmark process.
