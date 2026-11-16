---
id: UP-EX-014
title: A deploy script that says no — the testnet-only guard around Clearproof's pilot contracts
date: 2026-11-16
publishAfter: 2026-11-16T00:00:00Z
sourceCommit: 80c4b96dbae237322d998dcf7b4f871d5c5d8b95
claimRefs:
  - packages/contracts/scripts/deploy-pilot.ts
  - packages/contracts/scripts/pilot-deployment.ts
  - packages/contracts/scripts/legacy-verifier.ts
  - packages/contracts/scripts/networks.ts
  - packages/contracts/test/PilotDeployment.test.ts
  - tests/contract-scripts/pilot-deployment.test.ts
  - apps/docs/app/docs/deployment/page.mdx
status: approved
summary: The pilot deployment path added in PR #138 enforces three properties the usual deploy script leaves to the operator: it runs only on local and testnet chains and has no mainnet override, its privileged roles are explicit configuration rather than whoever holds the deployer key, and an interrupted deployment resumes from a manifest instead of redeploying. This explainer walks how each guard is implemented and why each one is a hard refusal rather than a warning.
canonical: /explainers/testnet-only-pilot-deployment
templateVersion: explainer-v1
---

Every deploy script has a set of things the operator is supposed to know. Don't
run this against mainnet. Don't reuse the deployer key for admin roles. Don't
rerun a half-finished deployment. Most projects write those rules down in a
runbook and rely on the person at the keyboard.

The pilot deployment path merged in
[PR #138](https://github.com/repfigit/clearproof/pull/138) in November 2026 took
a different position: if a rule is load-bearing, the script enforces it, and the
enforcement is a refusal, not a warning. This matters more than usual here
because of what the pilot verifier is. `PilotGroth16Verifier` is constructed
with proving keys whose embedded assurance label is
`development-unapproved` — they come from a development trusted setup, not the
documented multi-party ceremony that production keys require. A mainnet
deployment of that verifier would not be a mistake to warn about; it would be a
contract whose every accepted proof silently rests on unaudited keys. So
[`scripts/deploy-pilot.ts`](https://github.com/repfigit/clearproof/blob/main/packages/contracts/scripts/deploy-pilot.ts)
has no mainnet path at all, and no flag to create one.

The deployment logic itself lives in
[`scripts/pilot-deployment.ts`](https://github.com/repfigit/clearproof/blob/main/packages/contracts/scripts/pilot-deployment.ts),
with the network, signer, environment and file locations passed in as arguments.
That structure is not stylistic: it is what lets
[`PilotDeployment.test.ts`](https://github.com/repfigit/clearproof/blob/main/packages/contracts/test/PilotDeployment.test.ts)
and the
[contract-script suite](https://github.com/repfigit/clearproof/blob/main/tests/contract-scripts/pilot-deployment.test.ts)
run the real deployment function — including its refusals — without a chain,
and hold every script file to 100% coverage under
`npm run test:contract-scripts:coverage`.

## Two chain IDs, checked separately

The first guard has two layers, and the split is the interesting part.

The first layer never makes an RPC call. `pilotChainId` in
`pilot-deployment.ts` accepts exactly three kinds of names: the local Hardhat
networks (`hardhat`, `localhost`, chain 31337), and the entries of
[`scripts/networks.ts`](https://github.com/repfigit/clearproof/blob/main/packages/contracts/scripts/networks.ts)
marked `testnet: true` — sepolia, base-sepolia, arbitrum-sepolia,
polygon-amoy and optimism-sepolia. Every other name, including all five
mainnet entries the same file defines, throws before any network I/O happens.

The second layer assumes the first one passed anyway and checks reality. A
permitted network name is worth only what the RPC reports:
`assertPilotNetwork` compares the chain ID the connected provider returns
against the chain ID the name claims. A configuration error that points the
`sepolia` profile at a mainnet RPC endpoint is refused with the reported chain
ID in the message. The name is a convenience; the chain ID is the fact.

The same PR extended the same treatment to the legacy 16-signal path.
`prepareLegacyVerifier` — used by both `deploy.ts` and `deploy-multichain.ts`
— now calls `assertDevelopmentKeyChain`, which reads the chain ID from the RPC
and allows only local chains and `testnet: true` networks. The legacy verifier
also embeds development-only keys, so it gets the same no-override refusal.
One principle, applied to both profiles: nothing in either path can be talked
into a deployment the keys do not support.

## Admins are configuration, not accidents

The second guard is about who ends up with power. The two privileged
constructor arguments — the default admin of `PilotCurrentRegistry` and of
`PilotRootCheckpoint` — must be set explicitly, either as
`PILOT_REGISTRY_ADMIN` / `PILOT_CHECKPOINT_ADMIN` environment variables or as
`registryAdmin` / `checkpointAdmin` in the JSON file named by
`PILOT_DEPLOY_CONFIG`. If they are missing, the script stops.

The deployer address is used for a privileged role in exactly one case:
`PILOT_ALLOW_DEPLOYER_ADMIN=1`, which is itself only accepted on the local
Hardhat networks — on a public testnet the flag is refused even when set. The
error message states the rule directly: the deployer is never used for a
privileged role unless that flag is set on a local network. Zero addresses are
rejected as admin candidates, so the guard cannot be satisfied with a nullifier
of its own check.

Publishers are deliberately absent from the constructor. After deployment, each
admin assigns publishers per tenant with `setPublisher` — a separate,
reviewable transaction that increments the tenant epoch. The deploy script
sends no such transaction, so "deployed the contracts" and "granted a publisher
authority over a tenant" can never happen in one unreviewed step.

## The key arrives pinned

The verifier's proving key is not a file the script happens to find. The
operator names an artifact bundle (`PILOT_ARTIFACTS_DIR`) and supplies an
operator-reviewed manifest digest (`PILOT_MANIFEST_DIGEST`, 64 lowercase hex
characters). The script recomputes the manifest digest the same way
`src/prover/pilot_artifacts.py` does — the same pin the Python prover requires —
and checks the verification key file's SHA-256 and size against the manifest.
A swapped or truncated key file fails the deployment instead of silently
changing what the verifier will accept.

This is the deployment-side twin of the prover-side rule: the key that ends up
on chain is the key someone reviewed, identified by digest, not by filename.

## Confirm, then record, then resume

Before any transaction is sent, the script prints the full deployment plan —
network, chain ID, deployer, both admins, manifest digest, key commitment, git
commit (with a marker if the working tree is dirty), the exact contracts still
to deploy, and the manifest path — and requires the operator to type `deploy`.
Anything else aborts with no transaction sent. `SKIP_CONFIRM=1` exists for
scripted use and skips only that prompt.

Interruption is handled by a manifest per network,
`deployments/<network>-pilot.json`, written in a specific order: each
deployment transaction is recorded **before** it is awaited. If the process
dies between sending and confirming, the rerun does not redeploy. It fetches
the recorded transaction's receipt, verifies it succeeded with code at the
recorded address, and fills in the block number and runtime code hashes. A
contract whose receipt never confirmed stops the run with instructions rather
than being re-sent.

The resume path carries its own refusals:

- Recorded contracts are checked against the chain before anything new is
  sent — if the runtime code at a recorded address no longer matches the
  recorded hash, the run stops.
- A manifest that records a registry without its verifier is refused outright,
  because a new verifier cannot be attached to an existing registry.
- A resume must use the same deployer account and the same git commit that
  started the manifest; anything else is refused with both values printed.
- A deployer with zero balance is refused before the confirmation prompt.
- On the in-process Hardhat network, which starts empty on every run, a
  manifest from an earlier session cannot match reality and is refused; the
  documented way to run local trials is to point `CLEARPROOF_DEPLOYMENTS_DIR`
  at a scratch directory and not commit the resulting manifests.

The manifest also records what the rest of the system pins against: the
verifier's runtime `keccak256` (the value `PilotCurrentRegistry` stores as
`verifierCodeHash` and fails closed on), the runtime SHA-256 that
`scripts/publish_pilot_sanctions_head.py --runtime-sha256` takes, constructor
arguments, deployment transaction hashes, and the artifact manifest digest and
key commitment. The deployment record is the input to later trust checks, not
just a receipt.

## What the script does not do

Three absences are part of the design:

- No mainnet override, for either pilot or legacy deployment paths. The refusal
  message says why in the voice of the contract itself: the verifier embeds
  `development-unapproved` keys, so a mainnet deployment is never correct.
- No publisher assignment. Authority over tenants is granted in separate,
  individually reviewable transactions by the configured admins.
- No explorer verification and no automated post-deploy configuration beyond
  what the manifest records. The script deploys three contracts and documents
  them precisely; everything after that is a separate decision.

And one status fact worth stating plainly: as of this writing, no pilot
deployment has been performed or recorded. The scripts, tests and guardrails
are merged; the first real deployment is still ahead of the project.

## The takeaway

The general pattern is that deployment safety lives in documentation, and
documentation works until the day someone is in a hurry. The pilot deployment
path puts each load-bearing rule where it cannot be skipped: the chain allowlist
and the reported-chain-ID check refuse mainnet before a byte leaves the
machine, privileged roles require explicit configuration, the proving key is
identified by reviewed digest, and an interrupted run resumes from evidence
rather than optimism. `PilotDeployment.test.ts` asserts each refusal, so the
guards fail loudly if a future change weakens them — which is the difference
between a guardrail and a comment.
