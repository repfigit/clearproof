#!/usr/bin/env python3
"""Regenerate the compliance test-vector input for the BLS12-381 scalar field.

Poseidon is field-specific, so every hash-derived value in the committed
BN254 vector must be recomputed for BLS12-381. Structural values (amounts,
timestamps, thresholds, leaf ordering for the gap proof) carry over.
"""
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from scripts.generate_poseidon_constants import N_ROUNDS_F, N_ROUNDS_P  # noqa: E402

BLS_R = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def make_poseidon(p: int):
    # circomlib's poseidon.circom implements the OPTIMIZED (Neptune) Poseidon
    # with S/P constants derived mod BN254. Those derived constants satisfy
    # their algebraic identities only mod BN254, so over BLS12-381 the circuit
    # computes the OPT algorithm with BN254-derived C/S/M/P constants mod p.
    # Mirror that exactly (verified against the compiled circuit's wasm).
    raw = json.load(open(os.path.join(REPO_ROOT, "node_modules/circomlibjs/src/poseidon_constants_opt.json")))
    consts = {}
    for i, rp in enumerate(N_ROUNDS_P):
        t = i + 2
        consts[t] = (
            [int(x, 16) % p for x in raw["C"][i]],
            [int(x, 16) % p for x in raw["S"][i]],
            [[int(x, 16) % p for x in row] for row in raw["M"][i]],
            [[int(x, 16) % p for x in row] for row in raw["P"][i]],
        )

    def pow5(a: int) -> int:
        a2 = a * a % p
        return a2 * a2 % p * a % p

    def poseidon(inputs: list[int]) -> int:
        t = len(inputs) + 1
        C, S, M, P = consts[t]
        n_rounds_f = N_ROUNDS_F
        n_rounds_p = N_ROUNDS_P[t - 2]
        state = [0] + [v % p for v in inputs]
        state = [(a + C[i]) % p for i, a in enumerate(state)]
        for r in range(n_rounds_f // 2 - 1):
            state = [pow5(a) for a in state]
            base = (r + 1) * t
            state = [(a + C[base + i]) % p for i, a in enumerate(state)]
            state = [sum(M[j][i] * state[j] for j in range(t)) % p for i in range(t)]
        state = [pow5(a) for a in state]
        base = (n_rounds_f // 2) * t
        state = [(a + C[base + i]) % p for i, a in enumerate(state)]
        state = [sum(P[j][i] * state[j] for j in range(t)) % p for i in range(t)]
        stride = t * 2 - 1
        for r in range(n_rounds_p):
            state[0] = (pow5(state[0]) + C[(n_rounds_f // 2 + 1) * t + r]) % p
            s0 = sum(S[stride * r + j] * state[j] for j in range(t)) % p
            for k in range(1, t):
                state[k] = (state[k] + state[0] * S[stride * r + t + k - 1]) % p
            state[0] = s0
        for r in range(n_rounds_f // 2 - 1):
            state = [pow5(a) for a in state]
            base = (n_rounds_f // 2 + 1) * t + n_rounds_p + r * t
            state = [(a + C[base + i]) % p for i, a in enumerate(state)]
            state = [sum(M[j][i] * state[j] for j in range(t)) % p for i in range(t)]
        state = [pow5(a) for a in state]
        state = [sum(M[j][i] * state[j] for j in range(t)) % p for i in range(t)]
        return state[0]

    return poseidon


def merkle_root(poseidon, leaf: int, elements: list, indices: list) -> int:
    node = leaf
    for sib, idx in zip(elements, indices):
        sib = int(sib)
        node = poseidon([node, sib]) if int(idx) == 0 else poseidon([sib, node])
    return node


def main() -> None:
    inp = json.load(open(os.path.join(REPO_ROOT, "tests/vectors/compliance/input.json")))

    bn_poseidon = make_poseidon(BN254_R)
    # Sanity: reproduce the committed BN254 roots/commitment with our path logic.
    bn_root_left = merkle_root(
        bn_poseidon, int(inp["leftKey"]), inp["leftPathElements"], inp["leftPathIndices"]
    )
    assert str(bn_root_left) == inp["sanctionsTreeRoot"], f"BN254 left path root mismatch: {bn_root_left}"
    bn_root_right = merkle_root(
        bn_poseidon, int(inp["rightKey"]), inp["rightPathElements"], inp["rightPathIndices"]
    )
    assert str(bn_root_right) == inp["sanctionsTreeRoot"], "BN254 right path root mismatch"
    issuer_leaf_bn = bn_poseidon([2, int(inp["issuerDid"])])
    bn_issuer_root = merkle_root(
        bn_poseidon, issuer_leaf_bn, inp["issuerPathElements"], inp["issuerPathIndices"]
    )
    assert str(bn_issuer_root) == inp["issuerTreeRoot"], "BN254 issuer root mismatch"
    bn_commit = bn_poseidon(
        [int(inp["issuerDid"]), inp["kycTier"], inp["sanctionsClear"], inp["issuedAt"], inp["expiresAt"]]
    )
    assert str(bn_commit) == inp["credentialCommitment"], "BN254 commitment mismatch"
    bn_null = bn_poseidon([int(inp["credentialCommitment"]), int(inp["transferIdHash"])])
    assert str(bn_null) == inp["credentialNullifier"], "BN254 nullifier mismatch"
    print("BN254 self-check: all derived values reproduced")

    poseidon = make_poseidon(BLS_R)
    out = dict(inp)
    out["sanctionsTreeRoot"] = str(
        merkle_root(poseidon, int(inp["leftKey"]), inp["leftPathElements"], inp["leftPathIndices"])
    )
    right_root = merkle_root(poseidon, int(inp["rightKey"]), inp["rightPathElements"], inp["rightPathIndices"])
    assert str(right_root) == out["sanctionsTreeRoot"], "BLS tree root inconsistency between paths"
    issuer_leaf = poseidon([2, int(inp["issuerDid"])])
    out["issuerTreeRoot"] = str(
        merkle_root(poseidon, issuer_leaf, inp["issuerPathElements"], inp["issuerPathIndices"])
    )
    out["credentialCommitment"] = str(
        poseidon(
            [int(inp["issuerDid"]), inp["kycTier"], inp["sanctionsClear"], inp["issuedAt"], inp["expiresAt"]]
        )
    )
    out["credentialNullifier"] = str(poseidon([int(out["credentialCommitment"]), int(inp["transferIdHash"])]))

    # snake_case for the circuit
    mapping = {
        "sanctionsTreeRoot": "sanctions_tree_root", "issuerTreeRoot": "issuer_tree_root",
        "amountTier": "amount_tier", "transferTimestamp": "transfer_timestamp",
        "jurisdictionCode": "jurisdiction_code", "credentialCommitment": "credential_commitment",
        "tier2Threshold": "tier2_threshold", "tier3Threshold": "tier3_threshold",
        "tier4Threshold": "tier4_threshold", "domainChainId": "domain_chain_id",
        "domainContractHash": "domain_contract_hash", "transferIdHash": "transfer_id_hash",
        "credentialNullifier": "credential_nullifier", "proofExpiresAt": "proof_expires_at",
        "issuerDid": "issuer_did", "kycTier": "kyc_tier", "sanctionsClear": "sanctions_clear",
        "issuedAt": "issued_at", "expiresAt": "expires_at",
        "issuerPathElements": "issuer_path_elements", "issuerPathIndices": "issuer_path_indices",
        "walletAddressHash": "wallet_address_hash", "leftKey": "left_key", "rightKey": "right_key",
        "leftPathElements": "left_path_elements", "leftPathIndices": "left_path_indices",
        "rightPathElements": "right_path_elements", "rightPathIndices": "right_path_indices",
        "actualAmount": "actual_amount",
    }
    circuit_input = {mapping.get(k, k): (v if isinstance(v, list) else str(v)) for k, v in out.items()}
    out_path = os.path.join(REPO_ROOT, "tests/vectors/compliance-bls/input_bls.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    json.dump(circuit_input, open(out_path, "w"), indent=1)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
