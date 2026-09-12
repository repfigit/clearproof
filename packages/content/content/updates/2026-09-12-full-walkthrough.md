---
id: UP-2026-002
title: A complete transfer walkthrough exists in the source docs
date: 2026-09-12
publishAfter: 2026-09-12T14:30:00Z
sourceCommit: 57222b0bcad7e8dc06796fb870105a41ac87b844
claimRefs:
  - packages/content/content/recipes/full-walkthrough.md
  - packages/content/content/topics/quickstart.md
  - README.md
status: approved
summary: The merged pilot source includes a documented end-to-end walkthrough, from building the sanctions tree through issuing a credential, generating a proof and recording it on a testnet registry.
---

The source repository includes a [full end-to-end walkthrough](https://github.com/repfigit/clearproof/blob/main/packages/content/content/recipes/full-walkthrough.md)
covering the complete pilot flow: build the sanctions tree, issue a zkKYC
credential, generate a Groth16 compliance proof, verify it off-chain, and record
the verified result on a Sepolia [ComplianceRegistry](https://github.com/repfigit/clearproof/blob/main/packages/contracts/contracts/)
where a `ProofVerified` event can be checked with the bundled script.

Running it requires a local setup: the API with API-key auth, compiled circuit
artifacts, deployed contracts and a Sepolia RPC endpoint. The
[quickstart](https://github.com/repfigit/clearproof/blob/main/packages/content/content/topics/quickstart.md)
documents the prerequisites honestly — there is no guaranteed setup or proving
time, and the workflow uses synthetic data and testnet funds.

This walkthrough is a development pilot, not a production transfer
authorization. Circuits and contracts have not completed an independent audit,
and local proving artifacts use a development-only trusted setup. If you want to
see exactly what a Travel-Rule transfer-evidence flow looks like before
evaluating the cryptography, the walkthrough is the shortest supported path.
