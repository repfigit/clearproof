# SCRIPTS/ AGENTS.md

**Scope:** Operational / build scripts (not application code).

## OVERVIEW
Build, acceptance and operational scripts for reproducible proofs and sanctions data:

- `build_sanctions_tree.py` (563 LOC) — fetches OFAC + EU lists, normalizes crypto addresses, builds deterministic Poseidon Merkle tree, writes `artifacts/sanctions_tree.json` + test vectors.
- `build_pilot_sanctions_tree.py` — derives the pilot-transfer-v3 raw-address tree (`PilotSanctionsTree`, depth 20, key-sorted) from `artifacts/sanctions_tree.json` (or `--fetch`, reusing the legacy fetchers/normalizer) and writes `artifacts/pilot_sanctions_tree.json`; `--verify` rebuilds it from the published address list.
- `publish_pilot_sanctions_head.py` — human-confirmed publication of a signed `sanctions-root` approval for that tree as a `PilotCurrentRegistry` `Kind.Sanctions` head (default) or `PilotRootCheckpoint` approval. Dry-run with `--dry-run`.
- `compile_circuits.sh` — circom + snarkjs trusted setup pipeline. Downloads the audited Hermez ptau18 (sha256-pinned) by default; `CLEARPROOF_GENERATE_PTAU=1` opts into a local single-party ceremony. Dev zkeys are never byte-reproducible (snarkjs mixes OS randomness into every contribution).
- `poseidon_hash.js` — Node.js comparison helper; Python tree builders use native `src/registry/poseidon.py`.
- `regen_protobufs.sh` — regenerates gRPC stubs from `protos/` with pinned grpcio-tools + documented post-processing; `--check` mode runs in CI.
- `generate_verifier.mjs` — renders the Apache-2.0 `Groth16Verifier.sol` from a snarkjs verification key (replaces the GPL-3.0 snarkjs exporter; see docs/adr/0001). Never reintroduce `snarkjs zkey export solidityverifier`.

## KEY RULES (ALSO IN ROOT)

- **ENS names are NEVER resolved** — only raw hex addresses enter the sanctions tree (`normalize_address` enforces this).
- **Build script version** (`BUILD_SCRIPT_VERSION`) must be bumped on any normalization or tree logic change.
- **After running `build_sanctions_tree.py`** you **must** run the oracle relay (`make relay-sanctions` or equivalent) on all deployed chains. Skipping this is a critical anti-pattern (see root AGENTS.md).
- **The pilot tree is separate:** rebuild it with `build_pilot_sanctions_tree.py` and publish its signed root with `publish_pilot_sanctions_head.py` on every pilot deployment. The legacy oracle relay does not update pilot heads.
- Circuit compilation is a prerequisite for local proving; CI caches the Hermez ptau18 file.
- After `compile_circuits.sh`, the regenerated `Groth16Verifier.sol` and `tests/vectors/compliance/` (via `node packages/cli/dist/index.js demo --export tests/vectors/compliance`) must be committed together — they are one key set.

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| Rebuild sanctions Merkle root | `build_sanctions_tree.py` | Use `--verify` to check reproducibility against source SHA256 manifest |
| Change address normalization | `normalize_address()` in build script | Update `BUILD_SCRIPT_VERSION` and test vectors |
| Compile circuits locally | `compile_circuits.sh` | Requires circom + snarkjs in PATH |
| Compare Poseidon implementations | `poseidon_hash.js` | Parity helper; application hashing is native Python |

## ANTI-PATTERNS

- NEVER skip the sanctions relay step after a tree rebuild.
- NEVER resolve ENS names or use any name service when building the sanctions list.
- NEVER commit real `artifacts/sanctions_tree.json` containing live PII-derived data (the tree itself is public, but the build process must remain reproducible from public sources).

## COMMANDS (from root)

```bash
# Rebuild tree (fetches live lists)
python scripts/build_sanctions_tree.py

# Verify existing tree is reproducible
python scripts/build_sanctions_tree.py --verify

# Compile circuits
bash scripts/compile_circuits.sh
```

## NOTES

These scripts are intentionally kept outside the main packages so they can be run in minimal CI containers. All critical operational guidance (especially the "tree → relay" requirement) lives in the root AGENTS.md under ANTI-PATTERNS and COMMANDS. This file exists only to orient someone who has landed in the `scripts/` directory.
