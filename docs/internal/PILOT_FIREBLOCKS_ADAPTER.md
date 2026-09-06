# Fireblocks V2 adapter profile

Official documentation was checked September 6, 2026:

- [Signature validation](https://developers.fireblocks.com/reference/validating-webhooks)
  specifies detached JWS, the `Fireblocks-Webhook-Signature` header, RS512 and
  environment-specific JWKS endpoints. Verification signs the protected header
  and base64url encoding of the exact body bytes. New integrations use JWKS.
- [Migration guide](https://developers.fireblocks.com/reference/webhook-v2-migration-guide)
  identifies V2 notification ID, workspace ID, creation timestamp, event type,
  optional resource ID and transaction data.
- [Transaction events](https://developers.fireblocks.com/reference/webhooks-structures-eventtypes-transaction)
  describes transaction ID, external ID, asset, operation and status fields.
- [Best practices](https://developers.fireblocks.com/reference/webhooks-best-practices)
  advises deduplication by event ID, comparison of notification creation times,
  and tolerance for delivery reordering. Arrival order is not guaranteed.

`src.adapters.fireblocks.FireblocksVerifier` implements a bounded local profile
of those formats. The operator provides the correct environment's JWKS snapshot,
its independently approved validity interval and maximum notification age.
Keys are restricted to RSA/RS512 signature keys, 2048–4096 bits, at most sixteen
unique key IDs. The adapter does not fetch URLs or accept key references from
incoming headers. Provisioning and refreshing this trust inventory remains an
operator/integration responsibility; it is never derived from a webhook body.

The protected-header profile currently accepts exactly `alg` and `kid`, requires
canonical base64url detached JWS, and explicitly pins RS512. Other extensions,
legacy static-key signatures and embedded JWK/URL headers reject. PyJWT and its
cryptography backend perform the signature verification; raw bytes are parsed
only after verification. Duplicate JSON keys, nonfinite constants, oversized
bodies, wrong scopes and unsupported statuses return a generic error without
input values. The maximum body size is 64 KiB. The fixture's timestamps use Unix
milliseconds; the notification timestamp is retained as the sequence, and the
normalized event time is integer seconds.

An independent `FireblocksBinding` pins the workspace, provider transaction,
external transaction ID, provider asset ID, source ID and Clearproof transfer
scope. The adapter supports `TRANSFER` observations for `transaction.created`
and `transaction.status.updated`. It cannot establish this mapping from an
untrusted provider external ID alone. Unknown event/operation/status profiles
reject for review rather than being assigned a plausible successful state.

Current normalized custody mappings are:

| Provider state | Custody observation |
| --- | --- |
| SUBMITTED | created |
| BROADCASTING / CONFIRMING | submitted |
| COMPLETED | completed |
| FAILED | failed |
| CANCELLED | cancelled |

These are adapter decisions, not provider guarantees about other dimensions.
In particular, `COMPLETED` does not create a chain-finality, proof-validity,
counterparty-acceptance or compliance-approval event. Chain state requires its
own trusted observer. The adapter uses signed notification creation time for
ordering; equal-time distinct events conflict under the existing sequence
constraint and need explicit resolution. It never invents arrival sequences.

The output omits raw transaction addresses, amounts, notes and provider metadata.
Its evidence digest identifies the exact verified bytes. The adapter itself
neither logs nor persists them. The durable intake service below retains encrypted raw bodies and signatures;
independent historical key provenance remains open. A digest alone is not
retained evidence. Current internal event ingestion is
not a public provider webhook endpoint.

`tests/fixtures/fireblocks/transaction-status-v2.json` is a synthetic schema
fixture based on the documented fields, not a captured customer/provider event.
`tests/unit/test_fireblocks.py` signs it with an ephemeral local RSA key and
exercises verification, workspace/transaction/asset binding, byte tampering,
wrong keys, key expiry, duplicate keys/JSON and unsupported headers. No real
Fireblocks key, account, network transaction or production integration is used.
Provider-to-durable-store integration is described below. Authenticated JWKS
refresh, real fixture validation and the bilateral Travel Rule scenario remain
open CP-013 work.

## Durable verified intake

`src.services.fireblocks_intake.FireblocksIntake` joins the verifier to an
operator-configured `EventIngestionService`. It verifies the exact bytes and
binding first, then retains evidence and the normalized event in the same tenant
transaction. The internal event service still checks its source/actor grant.
There is no public Fireblocks webhook route or live account connection yet.

Migration 12 permits the encrypted `provider-evidence` record kind, writable
only by `events:ingest`. Raw bodies are split into 2,048-byte base64 chunks so
Unicode and large provider notes do not violate the store's canonical-string
limits. At most 32 chunks and one manifest are retained for the adapter's 64 KiB
input limit. Each record has a domain-separated digest and remains encrypted.

The manifest retains ordered chunk digests, raw-byte SHA-256 and size, exact
detached signature, selected public JWK/key ID, configured key validity/age
bounds and pinned transaction binding. The encrypted event references these
records and retains the original actor and receipt time. Those records capture
which configuration was used; they are not an independently signed historical
trust statement. Offline verification must receive trusted keys and time
sources independently of this manifest.

Chunk/manifest writes, normalized event and sequence index share one transaction.
A sequence conflict rolls back newly inserted evidence too. A byte-identical
source event retry preserves the first retained evidence and receipt time, even
if a later valid verification uses a different key snapshot. An existing event
without provider evidence cannot be silently treated as a provider-backed retry.

The PostgreSQL test verifies multi-chunk Unicode byte reconstruction after
reconnect, signature revalidation using independently retained test trust,
tenant isolation, ciphertext privacy, no chain-finality inference, retry
semantics and evidence rollback on a post-insert sequence conflict. This is a
local signed simulator flow; provider HTTP intake, JWKS refresh, historical
authority receipts and live interoperability still require separate work.
