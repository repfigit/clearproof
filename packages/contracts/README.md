# @clearproof/contracts

Solidity smart contracts for on-chain ZK compliance proof verification and registry management.

## Install

```bash
npm install @clearproof/contracts
```

## Deployed Contracts (Sepolia Testnet)

| Contract | Address |
|----------|---------|
| Groth16Verifier | `0x6F8e6f64C5601Eb25716f45C78c9B7C9c0bde8EA` |
| VASPRegistry | `0x99FE2813FD9D66Df43d1ce37d39341F5A7a557F0` |
| SanctionsOracle | `0x2822db7e67E1152a9cC81E44Df2182CA4662c7a2` |
| ComplianceRegistry | `0x941F7f188843279C03D1960821B4332A40e806F7` |
| SanctionsRootRelay | `0x911d8244F3b63a40040862dB0CC285A753036F87` |

> Verifier + ComplianceRegistry surgically redeployed 2026-07-20 (Apache-2.0 verifier, ADR 0001) via `scripts/redeploy-verifier.ts`; previous addresses in `deployments/sepolia.json` under `previous`.

## Development

```bash
cd packages/contracts
npx hardhat compile
npx hardhat test
```

## Links

- [Main repository](https://github.com/repfigit/clearproof)

## License

Apache-2.0


## Replacing a verifier through the existing router

From this workspace, run:

```bash
npx hardhat run scripts/redeploy-verifier.ts --network sepolia
```

The script checks the deployment record against the connected chain and registry.
It deploys a verifier and saves `pendingVerifierReplacement` before registering
it with the existing router. If the router timelock has not expired, the command
reports the activation timestamp and exits successfully with the replacement
pending. Run the same command again after that chain timestamp. An early retry
reuses the pending verifier without resetting the timelock.

After activation, the script updates the existing registry's selector and records
the old verifier and selector under `previous`. Stateful contract addresses and
registry domain binding remain unchanged. This does not establish compatibility
of old proofs with a new verification key.

Keep the pending record when retrying after a failed transaction or final record
write. The script checks current router/registry state to resume completed steps;
it refuses conflicting pending registrations, altered scope and a disabled
replacement verifier. A pending record is not an active deployment.
