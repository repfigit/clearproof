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
neither logs nor persists them. Encrypted raw-body/signature retention and
historical key provenance must be added at the durable webhook intake boundary;
a digest alone is not retained evidence. Current internal event ingestion is
not a public provider webhook endpoint.

`tests/fixtures/fireblocks/transaction-status-v2.json` is a synthetic schema
fixture based on the documented fields, not a captured customer/provider event.
`tests/unit/test_fireblocks.py` signs it with an ephemeral local RSA key and
exercises verification, workspace/transaction/asset binding, byte tampering,
wrong keys, key expiry, duplicate keys/JSON and unsupported headers. No real
Fireblocks key, account, network transaction or production integration is used.
Provider-to-durable-store integration, authenticated JWKS refresh, real fixture
validation and the bilateral Travel Rule scenario remain open CP-013 work.
