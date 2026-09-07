#!/usr/bin/env python3
"""Public synthetic-only EVM fixture; checkpoint labels are not source approvals."""

import argparse
import asyncio
import hashlib
import json
import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from src.protocol.canonical import record_digest
    from src.prover.pilot_artifacts import inspect_artifacts
    from src.prover.pilot_current import inspect_current_statement
    from src.prover.pilot_verifier import PilotPairingVerifier

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("registry_address")
    parser.add_argument("evaluated_at", type=int)
    args = parser.parse_args()
    directory = args.artifacts.resolve()
    artifacts = inspect_artifacts(
        directory, trusted_digest=(directory / "development-manifest-pin.txt").read_text().strip()
    )
    build = runpy.run_path(str(ROOT / "tests/unit/test_pilot_compliance.py"))["synthetic_case"]
    witness, context, inputs = build(
        artifact_manifest_digest=artifacts.manifest.digest,
        with_trust=True,
        authorization=True,
        evaluated_at=args.evaluated_at,
        deployment_address=args.registry_address,
    )
    node = Path(shutil.which("node"))
    bundle = ROOT / "node_modules/snarkjs/build/snarkjs.min.js"
    verifier = PilotPairingVerifier.load(
        artifacts, bundle_path=bundle, bundle_sha256=hashlib.sha256(bundle.read_bytes()).hexdigest(), node=node
    )
    with tempfile.TemporaryDirectory(prefix="clearproof-contract-fixture-") as temp:
        temporary = Path(temp)
        source, proof_path, signals_path = (temporary / name for name in ("input.json", "proof.json", "public.json"))
        source.write_text(json.dumps(witness))
        subprocess.run(
            [
                str(node),
                str(ROOT / "node_modules/snarkjs/cli.js"),
                "groth16",
                "fullprove",
                str(source),
                str(directory / artifacts.manifest.wasm.filename),
                str(directory / artifacts.manifest.proving_key.filename),
                str(proof_path),
                str(signals_path),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        proof, signals = proof_path.read_bytes(), json.loads(signals_path.read_bytes())
        inspection = asyncio.run(inspect_current_statement(verifier, proof, signals=signals, **inputs))
        if not inspection.cryptographic_valid:
            raise RuntimeError("Synthetic current proof did not verify")
    heads = []
    for name in ("issuance", "issuers", "sanctions"):
        snapshot = inputs[name].snapshot
        heads.append(dict(digest=snapshot.digest, value=snapshot.root))
    heads += [
        dict(
            digest=record_digest("clearproof/credential-checkpoint/v1", inputs["credential"].model_dump(mode="json")),
            value="0",
        ),
        dict(digest=context.policy_digest, value="0"),
        dict(
            digest=record_digest(
                "clearproof/valuation-checkpoint/v1", inputs["valuation_approval"].model_dump(mode="json")
            ),
            value="0",
        ),
    ]
    # Only test checkpoint mechanics here. A production publisher must authenticate
    # actual participant facts and ALLOW/information/recipient approval independently.
    for name, value in (("participants", "0"), ("authorization", "1")):
        heads.append(
            dict(
                digest=record_digest(
                    "clearproof/synthetic-checkpoint/v1", {"context_digest": context.digest, "kind": name}
                ),
                value=value,
            )
        )
    print(
        json.dumps(
            dict(
                scope="synthetic-contract-checkpoints",
                assurance="development-unapproved",
                python_current_valid=True,
                proof=json.loads(proof),
                signals=signals,
                context_digest=context.digest,
                transfer_digest=context.transfer_digest,
                evaluated_at=context.evaluated_at,
                valid_until=int(signals[5]),
                heads=heads,
            )
        )
    )


if __name__ == "__main__":
    main()
