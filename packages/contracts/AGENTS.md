# PACKAGES/CONTRACTS AGENTS.md

**Scope:** Solidity smart contracts + Hardhat tooling for on-chain ZK compliance verification and registry management.

## OVERVIEW
Hardhat workspace implementing Groth16 verifier, VASP registry, sanctions oracle, and compliance registry for multi-chain deployment.

## STRUCTURE
```
packages/contracts/
├── contracts/           # Solidity sources (6 contracts)
│   ├── Groth16Verifier.sol      # ~13k LOC — core verifier
│   ├── ComplianceRegistry.sol   # Proof submission + audit
│   ├── VASPRegistry.sol         # VASP identity + keys
│   ├── SanctionsOracle.sol      # Merkle root storage
│   ├── SanctionsRootRelay.sol   # Cross-chain root relay
│   └── ISanctionsRootReceiver.sol
├── scripts/             # Hardhat deployment + relay scripts
├── test/                # Hardhat test suite
├── deployments/         # JSON deployment records (per network)
└── typechain-types/     # Generated TS bindings (auto)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| New contract | `contracts/` + Hardhat test | Follow existing patterns |
| Multi-chain deploy | `scripts/deploy-multichain.ts` | Updates `deployments/` |
| Sanctions root update | `scripts/update-sanctions-root.ts` | Single network |
| Cross-chain relay | `scripts/relay-sanctions-root.ts` | All deployed networks |
| Contract interaction | `typechain-types/` (generated) | Never edit manually |

## CONVENTIONS
- **Solidity 0.8.24**, optimizer runs=200
- **Hardhat + ethers + typechain** for deployment and testing
- **Multi-network config** in `hardhat.config.ts` (testnets + mainnets)
- **Deployment records** stored in `deployments/<network>.json`
- **Never commit** `.env` or private keys

## ANTI-PATTERNS
- NEVER skip `make relay-sanctions` after root update — all chains must be consistent
- NEVER edit generated `typechain-types/` files
- NEVER deploy without updating `deployments/` records
- NEVER use ENS names in sanctions oracle — raw hex addresses only

## COMMANDS
```bash
cd packages/contracts

# Compile
npx hardhat compile

# Test
npx hardhat test

# Deploy (single network)
npx hardhat run scripts/deploy-multichain.ts --network arbitrum-sepolia

# Update sanctions root (single network)
npx hardhat run scripts/update-sanctions-root.ts --network ethereum

# Relay root to all deployed chains
npx ts-node scripts/relay-sanctions-root.ts
```

## NOTES
- Deployed addresses documented in `README.md` (Sepolia example)
- `SanctionsRootRelay` pattern enables consistent root across chains
- All contracts use deterministic deployment where possible
- Etherscan verification via `ETHERSCAN_API_KEY` in `.env`
