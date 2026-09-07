---
title: Smart Contracts
category: concepts
order: 4
cli-topic: contracts
---

# Smart Contracts

The project includes EVM proof verification, VASP registration, sanctions-root and compliance-recording contracts. Deployments listed here are **Sepolia testnet** records, not audited production infrastructure.

## Recorded deployments

The July 20, 2026 manifest records these addresses. Bytecode was present at all five on September 5, 2026. This check does not establish equivalence between every current source change and deployed bytecode.

| Contract | Sepolia address |
| --- | --- |
| Groth16Verifier | [0x6F8e6f64C5601Eb25716f45C78c9B7C9c0bde8EA](https://sepolia.etherscan.io/address/0x6F8e6f64C5601Eb25716f45C78c9B7C9c0bde8EA#code) |
| VASPRegistry | [0x99FE2813FD9D66Df43d1ce37d39341F5A7a557F0](https://sepolia.etherscan.io/address/0x99FE2813FD9D66Df43d1ce37d39341F5A7a557F0#code) |
| SanctionsOracle | [0x2822db7e67E1152a9cC81E44Df2182CA4662c7a2](https://sepolia.etherscan.io/address/0x2822db7e67E1152a9cC81E44Df2182CA4662c7a2#code) |
| ComplianceRegistry | [0x941F7f188843279C03D1960821B4332A40e806F7](https://sepolia.etherscan.io/address/0x941F7f188843279C03D1960821B4332A40e806F7#code) |
| SanctionsRootRelay | [0x911d8244F3b63a40040862dB0CC285A753036F87](https://sepolia.etherscan.io/address/0x911d8244F3b63a40040862dB0CC285A753036F87#code) |

## Groth16Verifier

Checks cryptographic proof validity against its verification key. That check alone does not establish source authenticity, current state, legal compliance or authorization to execute a transfer. Verifiers and artifacts must match the intended proof version.

## ComplianceRegistry

The development registry coordinates proof acceptance with other contracts. Its source checks duplicate transfer records, dependency pause/freshness, active VASP and submitting wallet, chain/contract domain, expiry and future timestamps, sanctions/issuer roots, transfer reference, configured thresholds, revocation and nullifier use. The current development code routes cryptographic verification through a versioned verifier router and configured selector.

Successful acceptance records the proof and consumes a nullifier. Read-only cryptographic verification in an SDK is a different operation. A recorded proof is not itself evidence of successful transfer settlement.

## VASPRegistry

Stores registered VASPs, authorized submitting wallets, jurisdictions, discovery endpoints and the issuer Merkle root. Registration and directory metadata must be interpreted under an explicit trust policy; they do not independently establish licensing or factual credential validity.

## SanctionsOracle

Stores a current root, update time, leaf count and bounded history. Controls include a one-hour update cooldown, a configured staleness window and a leaf-count floor. The history is a ring of up to 1,000 records, not a complete long-term evidence archive.

## SanctionsRootRelay

Forwards authorized root updates to the oracle. A local tree rebuild is not evidence that every intended chain received its update.

## Development

```bash
cd packages/contracts
npx hardhat compile
npx hardhat test
```

Use the ABI and deployment configuration for your exact target. Existing testnet addresses must not be represented as an independently audited production release.
