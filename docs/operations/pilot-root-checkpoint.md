# Pilot root checkpoint

`PilotRootCheckpoint` is a development Solidity registry for the current approved
snapshot digest, scalar root, approval revision and validity interval. It is
separate from the encrypted credential database. Tenant-specific publishers are
assigned by the contract admin; setting the publisher to zero disables future
publication. Updates compare the expected checkpoint revision and require a
strictly newer approval revision. Skipped unpublished revisions are permitted;
rollback and conflicting updates are rejected. Events retain publication facts.

The publisher must authenticate the registrar's signed snapshot and its source
policy before publication. The contract does not parse canonical JSON, verify
Ed25519 signatures, inspect credential membership or verify ZK proofs. Contract
administration and publisher custody are trust authorities. There is no production
deployment or audited-contract claim, and no automatic broadcast is enabled.

`publication_arguments()` authenticates a signed approval before constructing the
contract arguments. The tenant key is the domain-separated canonical tenant digest;
the root scope is the same canonical scope digest used in persistence, including
kind, issuer where applicable, chain, audience registry and credential profile.
The publisher must use the configured deployment and chain; this helper itself
neither selects a network nor sends a transaction.

`PilotCheckpointReader` verifies a signed approval against an operator-configured
checkpoint address, chain ID and runtime-bytecode SHA-256. Derive that pin from an
approved build/deployment artifact, never by trusting the queried RPC's own code.
It checks tenant, target proof-registry audience, root kind/issuer, key scope and
validity, then observes code and head at one numbered block. It compares digest,
root, revision and validity fields and rechecks the block hash to detect a changed
observation. The returned block number/hash identifies the evidence used. Reads
have a 30-second total deadline, do not cache acceptance, send transactions or
consume nullifiers.

The default block tag is `finalized`; `safe` or `latest` must be chosen explicitly.
The local test uses `latest` and does not demonstrate production finality. An
unsupported tag or RPC error propagates; there is no fallback to `latest`.
`max_block_age` bounds how stale the observed block may be. The supplied `now` must
come from the verifier's trusted clock. Approval lifetime must allow the selected
chain's finality delay: a short-lived approval may expire before it is finalized.

This is a trusted-RPC observation, not independent consensus verification. A
malicious RPC can fabricate chain data. Use an operator-trusted node/provider and
an appropriate finality policy. Signatures and database history alone are not a
replacement for this independent head source. Earlier block events plus trusted
historical chain evidence still need integration into offline bundles.

Run `npx hardhat test test/PilotRootCheckpoint.test.ts` from `packages/contracts`,
then `uv run python scripts/test_checkpoint_evm.py` from the repo root. The latter
compiles contracts, starts an owned ephemeral loopback node, deploys a fixture,
runs Python/contract parity checks and stops that node. Development node key logs
are suppressed. No shared network is deployed. The standalone CI job runs both.

Remaining gates include operator deployment manifests and publisher integration,
registrar-to-chain delivery/reconciliation, authenticated revocation handling and
composed transfer proof verification. A checkpoint does not make a revoked
credential usable; the current verifier still needs its revocation checks.
