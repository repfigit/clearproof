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
