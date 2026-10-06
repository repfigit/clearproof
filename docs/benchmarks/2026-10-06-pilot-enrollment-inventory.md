# Synthetic pilot enrollment inventory measurements

Measured October 6, 2026, with public synthetic EOA consent, encrypted records
and owned PostgreSQL 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1). Python 3.12.13 used
CPU affinity 0–3 on a shared Linux host. Each workload has three measured samples;
there is no separate warmup. Zero-tree nodes may be cached between counts. The
[JSON receipt](2026-10-06-pilot-enrollment-inventory.json) preserves every sample,
source SHA256, platform and exclusion. No customer records or secrets are used.

| Enrollments | First 64-entry page median | Complete depth-32 root median | Encrypted source pages |
| --- | --- | --- | --- |
| 64 | 0.755 s | 1.041 s | 0 |
| 256 | 0.722 s | 4.319 s | 0 |
| 512 | 0.740 s | 8.401 s | 4 |
| 1,024 | 0.768 s | 16.730 s | 8 |

Discovery checks complete index counts and validates 64 retained signatures and
live eligibility. Construction scans and authenticates the entire audience,
checks revocation, rebuilds the sparse Poseidon tree and packs the complete
source. The latter excludes registrar signing and persistence, proof generation,
HTTP/authentication, provider/chain work and concurrent tenant load. These are
latencies, not service throughput or production capacity guarantees.

The construction guard is 1,024 scanned records across every issuer configured
in a registrar refresh. Revoked/expired entries also consume that budget. A
30-second tenant transaction deadline remains independent. The measured largest
single-issuer scan fits that deadline; multi-issuer and production persistence
costs must still be validated on the deployment host. Start with smaller batches
and leave room for tenant lock contention and other work. Larger deployments need
further construction/storage changes and measurements, not a raised constant.

A separate real PostgreSQL test publishes a 258-enrollment paged source,
reconstructs a 32-sibling witness, generates the existing eight-signal proof and
independently verifies it. Missing source pages stop preparation. That acceptance
uses unapproved development artifacts and does not establish production assurance.

Reproduce from the repository root with a PostgreSQL account authorized to create
and remove an isolated synthetic schema; the benchmark removes only that schema:

```bash
# DATABASE_URL refers to your owned benchmark PostgreSQL, not customer storage.
PYTHONPATH=. taskset -c 0-3 uv run python docs/benchmarks/pilot_enrollment_inventory.py \
  --counts 64,256,512,1024 --samples 3 --output /tmp/inventory-measurements.json
```

The output path must not already exist. Raw credential/signature/wallet contents
are never emitted; the receipt contains aggregate timing and environment data.
