# @clearproof/contracts

Solidity sources and compiled ABIs for the Clearproof contracts. Nothing here is audited. No approved verification key exists: the legacy `Groth16Verifier` embeds a development key, and `PilotGroth16Verifier` takes its key at construction. The pilot contracts are not deployed on any network.

The package holds two separate sets of contracts. Do not treat a proof, root or record accepted by a legacy contract as a current pilot authorization.

## Install

```bash
npm install @clearproof/contracts
```

Sources are under `contracts/` and Hardhat artifacts (ABI and bytecode) under `artifacts/contracts/<Name>.sol/<Name>.json`. Test-only contracts (`MockVerifier`, `MockPilotVerifier`, `PairingHarness`) are in the repository and are not published in releases after 0.7.2.

## Pilot contracts (`pilot-transfer-v3`, current profile)

Not deployed anywhere. There is no committed deployment record and no deployment script for them in this package. The repository's tests and local acceptance run deploy them to a local development EVM only.

| Contract | Role |
|----------|------|
| `PilotGroth16Verifier` | Groth16/BN254 pairing check over the eight `pilot-transfer-v3` public signals. The verification key and artifact-manifest digest are fixed at construction. It reports `assurance = development-unapproved`. It does not reconstruct statements or consume nullifiers. |
| `PilotCurrentRegistry` | Per-tenant checkpoint heads, publisher-attested statement bindings, a read-only `inspect` and a `mirror` of authorization receipts. Checks `domain_chain_id` against `block.chainid` and `domain_registry` against its own address; the circuit does not constrain either. |
| `PilotRootCheckpoint` | Publisher-attested root-approval checkpoints (snapshot digest, root, revision, validity window). |
| `Pairing` | alt_bn128 pairing library used by both verifiers (MIT). |

Limits of the pilot contracts:

- PostgreSQL in the operator's gateway owns authorization consumption and replay protection. `PilotCurrentRegistry` only mirrors receipts that were already consumed. It cannot create an authorization.
- The registry trusts each tenant's publisher. It cannot detect a publisher that attests a false statement binding, and a passing pairing check alone is not an authorization.
- Both registries use OpenZeppelin `AccessControlDefaultAdminRules` and can be paused. Heads published under an earlier publisher epoch are not current.

See the [statement specification](https://github.com/repfigit/clearproof/blob/main/specs/pilot-transfer-v3.md), the [registry notes](https://github.com/repfigit/clearproof/blob/main/docs/internal/PILOT_CURRENT_REGISTRY.md) and the [root checkpoint guide](https://github.com/repfigit/clearproof/blob/main/docs/operations/pilot-root-checkpoint.md).

## Legacy contracts (16-signal demo profile)

`Groth16Verifier`, `VerifierRouter`, `ComplianceRegistry`, `VASPRegistry`, `SanctionsOracle`, `SanctionsRootRelay` and `ISanctionsRootReceiver` belong to the legacy `compliance.circom` demo path. `bench/Groth16VerifierBLS` is a BLS12-381 benchmark verifier, not a deployment candidate. The deployment and sanctions scripts in the repository (`scripts/deploy*.ts`, `update-sanctions-root.ts`, `relay-sanctions-root.ts`, `verify-onchain.ts`, `check-transfer.ts`, `redeploy-verifier.ts`) operate on these contracts only.

### Historical Sepolia deployment (July 20, 2026)

These addresses are the legacy 16-signal deployment in `deployments/sepolia.json`. They are not the 0.7.2 contracts, and the pilot contracts have no committed deployment. This registry was constructed without a `VerifierRouter`, so `scripts/redeploy-verifier.ts` does not apply. See the [verifier decommissioning guide](https://github.com/repfigit/clearproof/blob/main/docs/VERIFIER_DECOMMISSIONING.md).

| Contract | Address |
|----------|---------|
| Groth16Verifier | `0x6F8e6f64C5601Eb25716f45C78c9B7C9c0bde8EA` |
| VASPRegistry | `0x99FE2813FD9D66Df43d1ce37d39341F5A7a557F0` |
| SanctionsOracle | `0x2822db7e67E1152a9cC81E44Df2182CA4662c7a2` |
| ComplianceRegistry | `0x941F7f188843279C03D1960821B4332A40e806F7` |
| SanctionsRootRelay | `0x911d8244F3b63a40040862dB0CC285A753036F87` |

> On July 20, 2026 the verifier and ComplianceRegistry were replaced with the Apache-2.0 verifier (ADR 0001). The addresses that replacement retired are under `previous` in the same file.

### Replacing a legacy verifier through the existing router

From the `packages/contracts` workspace of a source checkout, run:

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
