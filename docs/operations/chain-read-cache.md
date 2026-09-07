# Chain reader cache (CP-002)

Each `ChainReader` owns its cache and a copy of its RPC/deployment configuration.
Construct separate readers for separate networks or registries. The environment
accessor creates a new reader when RPC URL, contract addresses or TTL change;
existing references keep their original configuration. Use each reader within a
single async event loop.

`CHAIN_CACHE_TTL` is read at construction, defaults to 30 seconds, and must be
finite and nonnegative. A constructor `cache_ttl` argument overrides it. Zero
disables caching. TTL uses a monotonic clock and starts before the RPC request,
so network delay cannot extend an observation's cache lifetime. A slow response
may return to its caller but is not cached after its TTL expires.

The default limit is 512 cached entries, with least-recently-used eviction;
`max_cache_entries` accepts a positive integer. False, zero roots and absent
records are legitimate cached results. Hash arguments are normalized to 32 bytes
before constructing keys. Caller changes to a returned record cannot mutate the
cached copy.

Concurrent requests for the same key share an RPC call. Cancelling one waiter
does not cancel other waiters. RPC/ABI errors propagate and are never cached or
represented as a missing proof. `get_proof_record()` uses the current public
`proofs(bytes32)` mapping and returns `transfer_id`, `proof_hash`, `verified_at`
and `verified`, or `None` for a zero timestamp.

Call `reader.invalidate_cache()` after observing a relevant confirmed state
change, a sanctions update, revocation or chain reorganization. Requests started
before invalidation may finish for their original callers, but cannot refill the
cache; new readers of that key will start a fresh request. Invalidation is local
to the reader. There is no Redis cache or automatic cross-process invalidation.

Cache TTL is not an oracle freshness check, finality rule or proof acceptance
policy. These methods read the provider's latest state independently, not an
atomic snapshot across contracts. Authorization must use the forthcoming
versioned verification context, approved roots and an explicit block/freshness
policy; do not infer those properties from a cached result.

Verification:

```bash
uv run python -m pytest tests/unit/test_chain_reader.py tests/unit/test_chain_reader_rpc.py -q
```

The cache tests cover reader isolation, expiry, zero/false/absent results,
concurrent calls, cancellation, invalidation while a request is pending, bounded
eviction and error propagation. The RPC fixture runs Web3's actual ABI encoder
and decoder against local deterministic responses and verifies target addresses.
It makes no network requests or transactions. The bundled method ABIs were
extracted from the current compiled Solidity contracts; no circuit or proving
artifact was changed.
