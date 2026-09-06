# Transfer event replay

`src.reconciliation.events` defines the first read-only investigation model.
`TransferScope` identifies an opaque business transfer inside a tenant and exact
EVM chain/registry deployment. Its domain-separated digest does not include a
policy revision, proof nonce or provider ID, so those changes need not split
one business investigation. The ingestion service must resolve and authorize
that mapping; accepting a supplied identifier does not prove ownership.

`TransferEvent` retains source identity, source event identity, per-dimension
source sequence, event time, ingestion time and an evidence digest separately.
It carries one state in one of six dimensions: compliance, proof, counterparty,
custody, chain or evidence. Unsupported states reject. A non-pending chain
observation must carry block number and hash; those are observations, not an
independent finality proof. Future source times require quarantine rather than
silent clock correction. No raw customer fields or free-text payloads belong
in this model. Treat the timeline and its opaque identifiers as tenant-private.

`reconcile(scope, events, now=...)` accepts at most 256 events and performs no
network, storage, transaction submission or authorization-consumption operation.
Its trust marker is `caller-required`: callers must authenticate sources and
validate their scope before replay. Event sequence must come from an accepted
source-ordering contract, never arrival order. Provider adapters without such
ordering need an explicit conflict/observation strategy rather than inventing
sequences from receipt time.

Replay rules:

- Same source/event identity and content is one event; retain the earliest
  observed ingestion timestamp across equivalent retries.
- Changed content under the same event identity, or distinct content under the
  same source/dimension/sequence, rejects the batch.
- Select the highest sequence per source and dimension. Out-of-order delivery
  cannot overwrite a newer source observation.
- Multiple sources with different current states or block identities produce
  an explicit conflict. Neither source wins because it arrived last.
- Missing dimensions remain unknown. States never imply another dimension's
  success. A reorganization can supersede an earlier finality observation.

The timeline sorts by source event time with stable source/sequence/ID tie
breakers. Findings include reason, owner, next action, source-event start time
and age at the supplied projection clock. Current findings cover source
conflicts, approval without submission, counterparty timeout, custody failure,
chain reorganization and reported finality with unresolved evidence. These are
investigation prompts, not executable remediation or legal decisions. A report
with no findings does not authorize a transfer or establish full compliance.

Unit tests enumerate all permutations of a multi-event lifecycle, replay
retries, reject conflicting duplicate identities/sequences, exercise tenant and
clock substitution, and distinguish complete, failed, timed-out and reorganized
observations. Durable internal ingestion is described below. Authenticated
provider adapters, provider links, full queue policy and CLI reports remain
open CP-012–CP-014 integration. No provider interoperability or
live account integration is claimed by these local replay tests.

## Durable internal ingestion

`EventIngestionService` receives the authenticated principal and an independently
configured tuple of `EventAuthority` grants. A grant names tenant, chain,
registry, source, allowed actors/dimensions and validity interval. Requests
cannot supply grants. Ingestion requires `events:ingest` and `evidence:decrypt`;
the source event contains no ingestion timestamp, which the server-side caller
supplies. Scope, actor, dimension and event/current time must fit a grant.
This authenticates an internal source operator, not a provider webhook signature.

Migration 11 adds `pilot_event_index`, referencing revision 1 of encrypted event
records. The index carries opaque tenant IDs, domain-separated identity/scope/
stream digests and sequence numbers; source IDs, reviewer identities and event
content remain encrypted. Identity is tenant/source/event, so one source event
cannot silently move between transfers. Sequence uniqueness is per tenant and
business-transfer/source/dimension stream. An index supports scoped loading
without scanning unrelated tenant events.

Ingestion holds the existing tenant transaction lock while checking duplicates,
writing the immutable encrypted event and inserting its index entry. Both writes
commit together. A changed identity or reused sequence raises a conflict and
rolls back; an identical retry returns the original ingestion time. At 256
unique events per transfer, further unique ingestion rejects rather than
silently truncating an investigation; retries still work. Larger histories need
an explicit pagination/archive design before increasing this pilot limit.

`investigate` requires `evidence:read` and `evidence:decrypt`, loads one tenant's
indexed records transactionally, checks their identities and then calls the
pure reconciler. It does not consume authorization, submit transactions or
contact counterparties. Stored provenance records the authenticated ingesting
actor, but does not yet retain independently verifiable historical authority
receipts. Revoking an actor does not erase prior evidence or prove it was false.

PostgreSQL tests cover concurrent duplicates, out-of-order delivery, reconnect,
sequence-conflict rollback after the encrypted insert, identity substitution,
source/actor/time/dimension rejection, ciphertext minimization and identical
provider IDs in separate tenants. A separate process-death test kills the
ingester after its encrypted insert and before index insertion, then checks
rollback and successful retry. Provider signatures, signed source provenance,
broader queue policy and the complete investigation CLI remain open acceptance work.

## Authenticated API

`POST /pilot/events/ingest` accepts a `SourceEvent` JSON record. It requires
`events:ingest` and `evidence:decrypt`, verifies the actor against server-owned
`PILOT_EVENT_AUTHORITIES` JSON (`{"authorities": [...]}`), and stamps ingestion
with the server clock. The authority inventory is bounded to 256 grants and
64 KiB; each grant uses the `EventAuthority` fields described above. Configuration
must be supplied by the operator, never copied from a request. Missing/invalid
configuration fails closed with 503. Unknown source/actor/scope grants return
403, conflicting identities/sequences 409, malformed events 422. Client-supplied
ingestion timestamps or extra personal-data fields reject without being echoed.

`POST /pilot/events/investigate` accepts `TransferScope`, requires `evidence:read`
and `evidence:decrypt`, and returns the retained timeline, independent states
and findings at the server clock. Its tenant must match the token. It requires
the database and encryption keyring, but can inspect retained events even when
new ingestion has been disabled by removing source grants. It performs no
external calls or writes. Reports remain private operational evidence, with
`caller-required` source trust; API authentication is not provider signature or
canonical-chain verification.

Uploads have ten-second deadlines and limits of 64 KiB for ingestion and 4 KiB
for investigation. The policy API now shares the same bounded body reader,
retaining its existing 1 MiB limit. Signed-JWT/PostgreSQL tests cover real role
checks, source grants, duplicate and conflicting events, server timestamps,
redacted errors, oversized bodies, reconnect and fail-closed configuration.

## Ageing queue API

`POST /pilot/events/queue` accepts a `QueueRequest` with optional `after` scope
digest, `limit` (1–16 indexed transfers, default 8) and `minimum_age_seconds`
(default 0). The authenticated principal needs `evidence:read` and
`evidence:decrypt`; no tenant selector is accepted in the body. Configuration
for new event ingestion is not needed to inspect retained observations.

The service scans indexed business transfers using tenant-scoped keyset
pagination and validates every loaded event's identity, scope digest and tenant.
Each page is loaded under the tenant transaction lock, then returns only matching
findings, independent states and opaque transfer scope. Full timelines and raw
provider evidence are omitted. Each item includes the oldest matching age;
findings retain reason, owner, next action, start time and current age.

`scanned_transfers` counts examined transfers, including those with no matching
findings. `next_cursor` advances by the last examined scope, not the last
returned item, so age filters cannot hide later pages. Clients must continue
while a cursor is present even if `items` is empty. Within a page, items sort by
oldest age descending with scope-digest ties. The explicit ordering value is
`scope-pages-age-within-page`; it does not promise global oldest-first ordering
across uncollected pages. Collect the pages before globally prioritizing results.

Pagination converges without omissions on unchanged data. New transfers inserted
before a cursor need a fresh scan, and each page has its own server `as_of`
clock; this is not a frozen cross-page historical snapshot. The queue only
covers transfers with retained indexed events. Event generation from every
upstream workflow remains integration work. Reads neither create events nor
consume authorizations or move funds.

Real PostgreSQL/JWT tests cover multi-page traversal, nonmatching transfers,
empty filtered pages with continuation, exact age boundaries, deterministic
ordering, reconnect, role rejection, tenant isolation and unchanged storage
counts. CLI rendering, provider links and broader queue decision rules remain
open CP-014 work.
