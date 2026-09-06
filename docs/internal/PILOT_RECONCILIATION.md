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
provider adapters, abrupt-restart acceptance, provider links, full queue policy
and API/CLI reports remain open CP-012–CP-014 integration. No provider interoperability or
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
provider IDs in separate tenants. Abrupt process death during ingestion,
authenticated HTTP ingestion, provider signatures, signed source provenance,
and the complete investigation API/CLI remain open acceptance work.
