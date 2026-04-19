# @clearproof/contracts

Solidity smart contracts for on-chain ZK compliance proof verification and registry management.

## Install

```bash
npm install @clearproof/contracts
```

## Deployed Contracts (Sepolia Testnet)

| Contract | Address |
|----------|---------|
| Groth16Verifier | `0x8ab9F1d446967BdE39bfE81B681E727EdcdF76Da` |
| VASPRegistry | `0x99FE2813FD9D66Df43d1ce37d39341F5A7a557F0` |
| SanctionsOracle | `0x2822db7e67E1152a9cC81E44Df2182CA4662c7a2` |
| ComplianceRegistry | `0xD038f2C6Ea7b414356Dc74C317cAE35Bc1c2b78a` |
| SanctionsRootRelay | _pending redeploy_ |

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
