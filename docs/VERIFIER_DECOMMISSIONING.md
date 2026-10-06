# Legacy verifier decommissioning

This runbook applies to the 16-signal legacy router and registry. It does not
change the current eight-signal pilot, approve keys, or authorize a production
migration. Execute transactions only for a reviewed deployment and its authorized
roles; retain transaction hashes, chain ID, runtime hashes and block timestamps.

## Prepare and activate a replacement

Use a new scheme/version selector, for example
`ethers.id("groth16-bn254-v2")`. A selector can bind to one address only, including
while pending and after retirement or emergency disable. The router pins its
runtime code at registration and checks it at activation and verification.
An EOA or empty selector is rejected. This router implements the legacy Groth16
ABI; another proof system needs a reviewed compatible adapter or a new router.

1. Deploy the reviewed verifier. Call
   `router.registerVerifier(selector, address, name)` with `ADMIN_ROLE`.
2. Read `router.timelocks(selector)` and wait for that chain timestamp. Call
   `router.activateVerifier(selector, name)`; check address, code hash and active
   state. Activation does not change the registry default.
3. With the registry administrator, call `registry.setVerifierSelector(selector)`.
   This schedules a swap; read `registry.verifierSelectionAfter()` and wait.
   The delay is at least the registry's deployment-time delay and the router's
   current minimum. Pending swaps can be cancelled with
   `registry.cancelVerifierSelection()`; they cannot be overwritten.
4. Call `registry.activateVerifierSelector()`. The target must still be active.
   Verify the new default, retained records and unchanged registry address.
   A retired verifier cannot be selected or used as the default.

`scripts/redeploy-verifier.ts` performs these stages for a v1-to-v2 replacement,
retains its pending address before registration, and resumes both real timelocks.
Rerun it after each recorded deadline. It never advances time on a remote chain.
It preserves the VASP registry, sanctions oracle, registry and their records.
Router retirement is a separate operator action described below.

The router rejects a zero constructor delay. `updateTimelock(value)` schedules a
change; `completeTimelockUpdate()` executes it after the existing delay. The
constructor's `timelockFloor` cannot be lowered. Read actual values rather than
assuming every deployment uses 24 hours.

## Drain in-flight proofs and retire

After cutover, `previousSelectorUntil(old)` is **cutover + 24 hours**, inclusive.
Clients may submit an older proof through
`registry.verifyAndRecordWithSelector(old, transferId, pA, pB, pC, signals, did)`.
The old declared transfer timestamp must be at or before
`previousSelectorCutoff(old)`. The same sender, chain, registry-address domain,
current roots, thresholds, expiry, credential revocation and shared nullifier
checks apply to both submission paths. Grace never revives stale or expired
proofs. The timestamp is a circuit statement, not independent evidence of when
the prover created the proof.

1. Check the old selector is no longer the default in every consuming registry.
   Record outstanding synthetic/evaluation submissions and contact participating
   operators through their approved process.
2. Call `router.scheduleRetirement(old)` and wait for `router.timelocks(old)`.
   Until completion, the verifier remains active.
3. Call `router.completeRetirement(old)`. It becomes non-default, with an inclusive
   router grace deadline of **completion + 24 hours**. The earlier of the
   registry and router deadlines governs acceptance. Declared transfer timestamps
   after `retiredAt` are rejected by the router.
4. At both deadlines, verify that old submissions reject and retained records
   remain readable. `getVerifier(old)` keeps the historical address forever;
   `isVerifierResolvable(old)` becomes false when router grace expires.
5. Remove the retired selector from new-proof configuration, release catalogues
   and operational allowlists. Preserve public metadata and receipt evidence.
   Record scheduled/completed transaction hashes and acceptance deadlines in the
   deployment record. A label or local `retiredAt` string is not shutdown proof.

The registry's grace applies only to former defaults selected through an actual
swap. It does not open acceptance to every verifier registered in the router.
A still-active backup can be selected again through another full delayed swap.
Retired or emergency-disabled bindings cannot be reactivated; deploy a reviewed
replacement under a fresh selector instead.

## Emergency shutdown

`router.disableVerifier(selector)` with `EMERGENCY_ROLE` terminates acceptance
immediately, including retirement grace. `router.pause()` stops all pairing
routes. Pausing the registry stops both submission methods; retained records
remain readable. Recovery through `unpause()` requires administrative authority;
it does not undo an individual disable. Schedule a reviewed active replacement
and wait its selection delay. Emergency authority never bypasses a swap delay.

## Historical Sepolia deployments

The committed `packages/contracts/deployments/sepolia.json` records chain
11155111, the July 20 Apache verifier replacement, and these older addresses:

| Component | Previous address | Recorded current legacy address |
| --- | --- | --- |
| Verifier | `0x8ab9F1d446967BdE39bfE81B681E727EdcdF76Da` | `0x6F8e6f64C5601Eb25716f45C78c9B7C9c0bde8EA` |
| Registry | `0xD038f2C6Ea7b414356Dc74C317cAE35Bc1c2b78a` | `0x941F7f188843279C03D1960821B4332A40e806F7` |

That manifest has **no router address**. These immutable deployed contracts do
not gain the new source behavior in place, and the replacement script refuses
to use an incompatible ABI. A new reviewed router/registry deployment is needed
once to enter this architecture; future compatible verifier swaps retain its
registry domain. Proofs bound to either older registry cannot be rebound by
changing public signals. Regenerate them for the new domain.

The manifest's historical `retiredAt` records a migration, not verified on-chain
shutdown. For each old registry, independently inspect code/ABI, administrator,
paused state, dependencies and any assets or approvals before recording an end
state. If an authorized pause exists, pause and retain its confirmed receipt.
Remove it from active clients and allowlists, verify rejected submissions, and
retain read-only records. Verifiers are read-only pairing contracts; discovering
an address or a successful pairing call does not grant it authority in a current
registry. Do not assert that an unsupported pause or self-destruct occurred.
No historical on-chain shutdown is claimed by this source change.
