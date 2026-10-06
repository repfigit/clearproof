#!/usr/bin/env python3
"""Compile and prove both profiles with isolated, unapproved development keys.

Circuit-derived source, keys and proving artifacts remain in the output directory.
Workspace builds may refresh normal generated outputs and contract bindings.
A local contribution is a reproducibility tool, not a production ceremony.
"""

import argparse
import hashlib
import json
import os
import runpy
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The committed legacy fixture is deliberately policy-negative. Reproduce every
# public signal from its private inputs rather than trusting a saved proof alone.
# All output, including the fresh verification key, stays in the development tree.
LEGACY_PARITY_PROGRAM = r"""
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { generateProof, verifyProof } from './packages/proof/dist/index.js';
const [artifacts, inputPath, publicPath, output] = process.argv.slice(1);
const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
const expected = JSON.parse(fs.readFileSync(publicPath, 'utf8'));
const wasm = path.join(artifacts, 'compliance_js/compliance.wasm');
const zkey = path.join(artifacts, 'compliance_final.zkey');
const vkey = path.join(artifacts, 'verification_key.json');
const phase1 = fs.readFileSync(path.join(artifacts, '../ptau-sha256.txt'), 'utf8').trim();
const generated = await generateProof(input, wasm, zkey);
if (JSON.stringify(generated.publicSignals) !== JSON.stringify(expected)) {
  throw new Error('Development legacy parity: input-derived public signals diverge from fixture');
}
const verified = await verifyProof(generated.proof, generated.publicSignals, vkey);
if (!verified.proofValid || verified.valid || !verified.rejectionReasons.includes('threshold_mismatch')) {
  throw new Error('Development legacy parity: expected pairing-valid, policy-negative proof');
}
fs.mkdirSync(output);
fs.copyFileSync(inputPath, path.join(output, 'input.json'));
fs.writeFileSync(path.join(output, 'proof.json'), JSON.stringify(generated.proof, null, 2) + '\n');
fs.writeFileSync(path.join(output, 'public.json'), JSON.stringify(generated.publicSignals, null, 2) + '\n');
fs.copyFileSync(vkey, path.join(output, 'verification_key.json'));
const sha256 = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const manifest = {
  description: 'Re-derived legacy compliance parity vector; threshold-policy rejection is intentional',
  circuit: 'compliance', proofSystem: 'groth16', curve: 'bn128',
  devKeysOnly: true,
  warning: 'UNAPPROVED single-party development phase-2 keys. NOT valid for production.',
  artifacts: { wasm_sha256: sha256(wasm), zkey_sha256: sha256(zkey), vkey_sha256: sha256(vkey) },
  files: Object.fromEntries(['input.json', 'proof.json', 'public.json', 'verification_key.json']
    .map(name => [name, sha256(path.join(output, name))])),
  phase1_sha256: phase1,
  expected_public_sha256: sha256(publicPath),
  all_public_signals_reproduced: true, pairing_valid: true, policy_valid: false,
};
fs.writeFileSync(path.join(output, 'MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('UNAPPROVED legacy parity: all 16 input-derived signals match; pairing passes; policy rejects');
process.exit(0);
"""


def run(*args, cwd=ROOT, env=None, timeout=1800):
    # Arguments are development artifact paths/options, never customer inputs.
    print("Development step:", " ".join(str(arg) for arg in args), flush=True)
    started = time.monotonic()
    process = subprocess.Popen([str(arg) for arg in args], cwd=cwd, env=env, start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
        if code:
            raise subprocess.CalledProcessError(code, process.args)
    finally:
        # Kill the owned group on timeout/interruption, including worker children.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        print(f"Development step elapsed: {time.monotonic() - started:.1f}s", flush=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New directory for unapproved development artifacts")
    parser.add_argument(
        "--prepared-ptau", type=Path, help="Explicit local development input; never production approval"
    )
    args = parser.parse_args()
    output = args.output.absolute()
    # Refuse reuse or overwrite, including existing symlinks.
    output.mkdir(parents=True, exist_ok=False)
    node = shutil.which("node")
    circom = shutil.which("circom")
    if not node or not circom:
        raise SystemExit("Node and Circom must be installed")
    cli = ROOT / "node_modules/snarkjs/build/cli.cjs"
    if not cli.is_file():
        raise SystemExit("Install the repository dependencies before running")
    (output / "DEVELOPMENT-ONLY.txt").write_text(
        "UNAPPROVED development keys. No audit or production ceremony.\n"
        "Policy schema binding is structural, not policy approval or authorization.\n"
    )
    ptau = output / "UNAPPROVED-final.ptau"
    if args.prepared_ptau:
        shutil.copyfile(args.prepared_ptau, ptau)
    else:
        initial = output / "UNAPPROVED-initial.ptau"
        contributed = output / "UNAPPROVED-contributed.ptau"
        run(node, cli, "powersoftau", "new", "bn128", "17", initial)
        run(
            node,
            cli,
            "powersoftau",
            "contribute",
            initial,
            contributed,
            "--name=Clearproof CI development only",
            "-e=unapproved-ci-development-not-a-production-ceremony",
        )
        run(node, cli, "powersoftau", "prepare", "phase2", contributed, ptau, "-v", timeout=5400)
        initial.unlink()
        contributed.unlink()
    (output / "ptau-sha256.txt").write_text(digest(ptau) + "\n")

    for name, source in (("legacy", "compliance"), ("pilot", "pilot_compliance")):
        target = output / name
        target.mkdir()
        run(circom, ROOT / f"circuits/{source}.circom", "--r1cs", "--wasm", "--sym", "-o", target)
        run(node, cli, "groth16", "setup", target / f"{source}.r1cs", ptau, target / "initial.zkey")
        key = target / ("compliance_final.zkey" if name == "legacy" else "UNAPPROVED-development.zkey")
        run(
            node,
            cli,
            "zkey",
            "contribute",
            target / "initial.zkey",
            key,
            "--name=Clearproof CI phase two development only",
            "-e=unapproved-ci-phase-two-development",
        )
        (target / "initial.zkey").unlink()
        vkey = target / ("verification_key.json" if name == "legacy" else "verification-key.json")
        run(node, cli, "zkey", "export", "verificationkey", key, vkey)
        run(node, ROOT / "scripts/generate_verifier.mjs", vkey, target / "Groth16Verifier.sol")

    # Preserve the existing legacy CLI smoke check using fresh, matching files.
    for workspace in ("content", "proof", "cli"):
        directory = ROOT / f"packages/{workspace}"
        compiler = subprocess.check_output(
            [node, "-e", "process.stdout.write(require.resolve('typescript/bin/tsc'))"],
            cwd=directory,
            text=True,
            timeout=30,
        )
        run(node, compiler, cwd=directory)
    run(node, ROOT / "packages/cli/dist/index.js", "demo", "--artifacts", output / "legacy")
    run(
        node,
        "--input-type=module",
        "-e",
        LEGACY_PARITY_PROGRAM,
        output / "legacy",
        ROOT / "tests/vectors/compliance/input.json",
        ROOT / "tests/vectors/compliance/public.json",
        output / "legacy/regenerated-parity",
    )

    # Reproduce the composed profile from synthetic fixtures, without private data.
    from src.policy.model import POLICY_SCHEMA_DIGEST
    from src.prover.pilot_artifacts import PilotArtifactManifest, inspect_artifacts
    from src.prover.pilot_compliance import PROFILE, PUBLIC_SIGNALS

    pilot = output / "pilot"
    shutil.copyfile(pilot / "pilot_compliance_js/pilot_compliance.wasm", pilot / "pilot_compliance.wasm")
    # This digest identifies a source inventory; it is not a reproducible-build attestation.
    sources = {
        str(p.relative_to(ROOT)): digest(p)
        for folder in (ROOT / "circuits", ROOT / "node_modules/circomlib/circuits")
        for p in sorted(folder.rglob("*.circom"))
    }
    source_bytes = json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
    (output / "source-inventory.json").write_bytes(source_bytes)
    value = {
        "proof_profile": PROFILE,
        "policy_schema_digest": POLICY_SCHEMA_DIGEST,
        "source_bundle_digest": hashlib.sha256(source_bytes).hexdigest(),
        "compiler_sha256": digest(Path(circom)),
        "public_signals": list(PUBLIC_SIGNALS),
    }
    for role, filename in (
        ("wasm", "pilot_compliance.wasm"),
        ("r1cs", "pilot_compliance.r1cs"),
        ("proving_key", "UNAPPROVED-development.zkey"),
        ("verification_key", "verification-key.json"),
    ):
        path = pilot / filename
        value[role] = {"filename": filename, "sha256": digest(path), "size": path.stat().st_size}
    raw = json.dumps(value).encode()
    manifest = PilotArtifactManifest.model_validate_json(raw)
    (pilot / "manifest.json").write_bytes(raw)
    (pilot / "development-manifest-pin.txt").write_text(manifest.digest)
    inspected = inspect_artifacts(pilot, trusted_digest=manifest.digest)
    fixture = runpy.run_path(str(ROOT / "tests/unit/test_pilot_compliance.py"))
    witness, context, _ = fixture["synthetic_case"](artifact_manifest_digest=manifest.digest, with_trust=True)
    (pilot / "synthetic-context.json").write_text(context.model_dump_json())
    inspected.check_artifact_context(context)
    (pilot / "synthetic.json").write_text(json.dumps(witness))
    (pilot / "expected-public.json").write_text(json.dumps([witness[name] for name in PUBLIC_SIGNALS]))
    run(
        node,
        pilot / "pilot_compliance_js/generate_witness.js",
        pilot / "pilot_compliance_js/pilot_compliance.wasm",
        pilot / "synthetic.json",
        pilot / "synthetic.wtns",
    )
    run(
        node,
        cli,
        "groth16",
        "prove",
        pilot / "UNAPPROVED-development.zkey",
        pilot / "synthetic.wtns",
        pilot / "proof.json",
        pilot / "public.json",
    )
    run(
        sys.executable,
        "-m",
        "pytest",
        "tests/integration/test_pilot_pairing.py",
        "tests/integration/test_pilot_proving.py",
        "tests/integration/test_legacy_verifier.py",
        "tests/integration/test_api_real_circuit.py",
        "-q",
        env={
            **os.environ,
            "CLEARPROOF_PILOT_TEST_ARTIFACTS": str(pilot),
            "CLEARPROOF_LEGACY_TEST_ARTIFACTS": str(output / "legacy"),
        },
    )
    # Exercise the same fresh eight-signal proof on the local EVM. Never deploy to
    # a configured remote network and never copy development keys into source.
    contracts = ROOT / "packages/contracts"
    hardhat = subprocess.check_output(
        [node, "-e", "process.stdout.write(require.resolve('hardhat/internal/cli/cli'))"],
        cwd=contracts,
        text=True,
        timeout=30,
    )
    run(
        node,
        hardhat,
        "test",
        "--network",
        "hardhat",
        "test/PilotGroth16Verifier.test.ts",
        "test/PilotCurrentRegistry.test.ts",
        "test/E2E.test.ts",
        cwd=contracts,
        env={
            **os.environ,
            "CLEARPROOF_PILOT_TEST_ARTIFACTS": str(pilot),
            "CLEARPROOF_LEGACY_TEST_ARTIFACTS": str(output / "legacy"),
            "CLEARPROOF_TEST_PYTHON": sys.executable,
        },
    )
    print("Development round trips passed; artifacts remain unapproved:", output, flush=True)


if __name__ == "__main__":
    main()
