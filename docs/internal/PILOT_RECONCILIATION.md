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
observations. Durable append-only ingestion, authenticated provider adapters,
transactional restart behavior, provider links, full queue policy and API/CLI
reports remain open CP-012–CP-014 integration. No provider interoperability or
live account integration is claimed by these local replay tests.
