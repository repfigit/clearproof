"""Frozen pre-audit circuit profile manifest schema and fail-closed validator.

This module pins the pre-audit circuit surface (ADR 0002 open task 3, ADR 0004
panel path item 2, AIF-67 wallet-ownership composition) before any production
MPC ceremony or audit freeze:

  - Every circuit in the profile (entry file, source bundle hashes, public
    signal schema digest, tree depths, constraint/wire counts, R1CS digest).
  - Curve and scalar field parameters (BN254 pilot baseline + BLS12-381
    target curve with curve-correct Poseidon parameters).
  - Poseidon round-constant and MDS/Circom-constant digests.
  - Explicit pre-audit / non-production assurance status (no ceremony keys).

The validator fails closed on any schema, hash, signal, depth, curve, Poseidon,
or source-file drift. It never approves production keys or runs a ceremony.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.protocol.canonical import record_digest
from src.protocol.transfer import Hex32
from src.prover.pilot_compliance import PROFILE as PILOT_PROFILE
from src.prover.pilot_compliance import PUBLIC_SIGNALS as PILOT_PUBLIC_SIGNALS
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, ISSUER_TREE_DEPTH, SANCTIONS_TREE_DEPTH
from src.registry.poseidon import BLS12_381_SCALAR_FIELD, BN254_SCALAR_FIELD

PREAUDIT_MANIFEST_PATH = Path("specs/preaudit-circuit-profile-v1.json")
PREAUDIT_MANIFEST_VERSION = "clearproof-preaudit-circuit-profile-v1"

WALLET_OWNERSHIP_PUBLIC_SIGNALS: tuple[str, ...] = (
    "extension_commitment",
    "expected_credential_commitment",
    "expected_attestation_digest",
    "evaluated_at",
)

PILOT_EXPECTED_DEPTHS: dict[str, int] = {
    "issuance": ISSUANCE_TREE_DEPTH,
    "issuer": ISSUER_TREE_DEPTH,
    "sanctions": SANCTIONS_TREE_DEPTH,
}

CURVE_PRIMES: dict[str, tuple[int, int]] = {
    "bn254": (BN254_SCALAR_FIELD, 254),
    "bls12-381": (BLS12_381_SCALAR_FIELD, 255),
}

_SAFE_REL_PATH = re.compile(r"^(?!/)(?!.*\.\.)[A-Za-z0-9._/-]+$")


class ProfileValidationError(ValueError):
    """Fail-closed diagnostic code for pre-audit profile drift or tampering."""


class _StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PinnedFile(_StrictRecord):
    path: str
    sha256: Hex32
    size: int = Field(ge=1)

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        if not _SAFE_REL_PATH.fullmatch(value):
            raise ValueError("Unsafe relative path")
        return value


class CurveParameters(_StrictRecord):
    curve: Literal["bn254", "bls12-381"]
    circom_prime: Literal["bn128", "bls12381"]
    scalar_field_order: str
    scalar_field_bits: int = Field(ge=254, le=255)
    poseidon_sbox_power: Literal[5] = 5
    poseidon_full_rounds: Literal[8] = 8
    poseidon_partial_rounds: tuple[int, ...]
    poseidon_constants_json: PinnedFile
    poseidon_circom_constants: PinnedFile | None = None

    @model_validator(mode="after")
    def match_curve_parameters(self) -> CurveParameters:
        expected_prime, expected_bits = CURVE_PRIMES[self.curve]
        expected_circom = "bn128" if self.curve == "bn254" else "bls12381"
        if self.circom_prime != expected_circom:
            raise ValueError("Curve / circom prime mismatch")
        if self.scalar_field_bits != expected_bits:
            raise ValueError("Curve / scalar field bit-width mismatch")
        if self.scalar_field_order != str(expected_prime):
            raise ValueError("Curve / scalar field order mismatch")
        if len(self.poseidon_partial_rounds) != 16:
            raise ValueError("Poseidon partial round table must cover t=2..17")
        if self.curve == "bls12-381" and self.poseidon_circom_constants is None:
            raise ValueError("BLS12-381 curve requires curve-correct Circom Poseidon constants")
        return self


class PublicSignalEntry(_StrictRecord):
    name: str
    meaning: str = Field(min_length=1, max_length=256)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", value):
            raise ValueError("Invalid public signal name")
        return value


class CircuitEntry(_StrictRecord):
    circuit_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    role: Literal["transfer-compliance", "wallet-ownership-extension"]
    profile_name: str = Field(min_length=1, max_length=64)
    curve: Literal["bn254", "bls12-381"]
    entry_circuit: str
    source_files: tuple[PinnedFile, ...]
    public_signals: tuple[PublicSignalEntry, ...]
    public_signal_schema_digest: Hex32
    tree_depths: dict[str, int]
    domain_tags: dict[str, int]
    r1cs_constraints: int = Field(ge=1)
    r1cs_wires: int = Field(ge=1)
    r1cs_sha256: Hex32
    artifact_status: Literal["compiled-r1cs-pinned", "pending-ceremony"] = "compiled-r1cs-pinned"
    ceremony_status: Literal["unapproved-preaudit-no-ceremony"] = "unapproved-preaudit-no-ceremony"

    @field_validator("entry_circuit")
    @classmethod
    def safe_entry(cls, value: str) -> str:
        if not _SAFE_REL_PATH.fullmatch(value) or not value.endswith(".circom"):
            raise ValueError("Invalid entry circuit path")
        return value

    @model_validator(mode="after")
    def consistent_circuit(self) -> CircuitEntry:
        paths = [f.path for f in self.source_files]
        if len(set(paths)) != len(paths) or self.entry_circuit not in paths:
            raise ValueError("source_files must be unique and include entry_circuit")
        names = [s.name for s in self.public_signals]
        if len(set(names)) != len(names) or not names:
            raise ValueError("public_signals must be non-empty and unique")
        if any(type(v) is not int or v < 1 for v in self.tree_depths.values()):
            raise ValueError("Invalid tree depth")
        if any(type(v) is not int or v < 1 for v in self.domain_tags.values()):
            raise ValueError("Invalid domain tag")
        expected_digest = signal_schema_digest(
            circuit_id=self.circuit_id,
            profile_name=self.profile_name,
            curve=self.curve,
            public_signals=self.public_signals,
            tree_depths=self.tree_depths,
            domain_tags=self.domain_tags,
        )
        if not hmac.compare_digest(self.public_signal_schema_digest, expected_digest):
            raise ValueError("public_signal_schema_digest mismatch")
        return self


class ToolchainPin(_StrictRecord):
    circom_version: str = Field(min_length=1, max_length=32)
    circom_linux_amd64_sha256: Hex32
    snarkjs_version: str = Field(min_length=1, max_length=32)
    circomlib_version: str = Field(min_length=1, max_length=32)


class PreauditCircuitProfile(_StrictRecord):
    schema_version: Literal["clearproof-preaudit-circuit-profile-v1"] = PREAUDIT_MANIFEST_VERSION
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    assurance: Literal["preaudit-frozen-no-ceremony"] = "preaudit-frozen-no-ceremony"
    pilot_signals_source: PinnedFile
    toolchain: ToolchainPin
    curves: dict[Literal["bn254", "bls12-381"], CurveParameters]
    circuits: tuple[CircuitEntry, ...]

    @model_validator(mode="after")
    def verify_composition(self) -> PreauditCircuitProfile:
        if set(self.curves) != {"bn254", "bls12-381"}:
            raise ValueError("Profile must pin both bn254 and bls12-381 curve parameters")
        for key, spec in self.curves.items():
            if spec.curve != key:
                raise ValueError("Curve map key mismatch")
        ids = [c.circuit_id for c in self.circuits]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate circuit_id entries")
        by_id = {c.circuit_id: c for c in self.circuits}
        required_ids = {
            "pilot-transfer-v3-bn254",
            "wallet-ownership-v1-bn254",
            "wallet-ownership-v1-bls12381",
        }
        if not required_ids <= set(by_id):
            raise ValueError("Profile is missing required pilot-transfer-v3 or AIF-67 circuits")

        pilot = by_id["pilot-transfer-v3-bn254"]
        if pilot.profile_name != PILOT_PROFILE:
            raise ValueError("pilot-transfer-v3 profile name drifted")
        if tuple(s.name for s in pilot.public_signals) != PILOT_PUBLIC_SIGNALS:
            raise ValueError("pilot-transfer-v3 public signal layout drifted")
        if pilot.tree_depths != PILOT_EXPECTED_DEPTHS:
            raise ValueError("pilot-transfer-v3 tree depths drifted")

        for cid, expected_curve in (
            ("wallet-ownership-v1-bn254", "bn254"),
            ("wallet-ownership-v1-bls12381", "bls12-381"),
        ):
            wallet = by_id[cid]
            if wallet.curve != expected_curve:
                raise ValueError(f"{cid} curve mismatch")
            if tuple(s.name for s in wallet.public_signals) != WALLET_OWNERSHIP_PUBLIC_SIGNALS:
                raise ValueError(f"{cid} public signal layout drifted")
            if wallet.domain_tags.get("wallet_ownership_extension") != 111:
                raise ValueError(f"{cid} domain tag drifted")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/preaudit-profile/v1", self.model_dump(mode="json"))


def signal_schema_digest(
    *,
    circuit_id: str,
    profile_name: str,
    curve: str,
    public_signals: tuple[PublicSignalEntry, ...],
    tree_depths: dict[str, int],
    domain_tags: dict[str, int],
) -> str:
    payload = {
        "circuit_id": circuit_id,
        "profile_name": profile_name,
        "curve": curve,
        "public_signals": [{"name": s.name, "meaning": s.meaning} for s in public_signals],
        "tree_depths": dict(sorted(tree_depths.items())),
        "domain_tags": dict(sorted(domain_tags.items())),
    }
    return record_digest("clearproof/circuit-signal-schema/v1", payload)


def _strict_json_load(raw: bytes) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProfileValidationError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ProfileValidationError("invalid_json_constant")

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)
    except ProfileValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileValidationError("invalid_json") from exc
    if type(parsed) is not dict:
        raise ProfileValidationError("manifest_must_be_object")
    return parsed


def _sha256_file(path: Path) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ProfileValidationError(f"missing_or_invalid_file:{path.name}")
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def _check_pinned_file(root: Path, entry: PinnedFile) -> None:
    target = (root / entry.path).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ProfileValidationError(f"path_escape:{entry.path}") from exc
    actual_sha, actual_size = _sha256_file(root / entry.path)
    if actual_size != entry.size:
        raise ProfileValidationError(f"size_drift:{entry.path}")
    if not hmac.compare_digest(actual_sha, entry.sha256):
        raise ProfileValidationError(f"hash_drift:{entry.path}")


def validate_preaudit_profile(
    root: Path,
    manifest_rel: Path = PREAUDIT_MANIFEST_PATH,
    *,
    trusted_digest: str | None = None,
    r1cs_dir: Path | None = None,
) -> PreauditCircuitProfile:
    """Load and verify the frozen pre-audit circuit profile against ``root``.

    Fails closed on any schema violation, digest mismatch, or file drift.
    When ``r1cs_dir`` is supplied, also checks compiled ``<entry_stem>.r1cs``
    hashes against each circuit's pinned ``r1cs_sha256``.
    """
    root = root.resolve()
    manifest_path = root / manifest_rel
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ProfileValidationError("manifest_unavailable")
    raw = manifest_path.read_bytes()
    _strict_json_load(raw)
    try:
        profile = PreauditCircuitProfile.model_validate_json(raw)
    except ValueError as exc:
        raise ProfileValidationError(f"invalid_manifest:{exc}") from exc

    if trusted_digest is not None:
        if type(trusted_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", trusted_digest):
            raise ProfileValidationError("invalid_trust_pin")
        if not hmac.compare_digest(profile.digest, trusted_digest):
            raise ProfileValidationError("untrusted_manifest_digest")

    _check_pinned_file(root, profile.pilot_signals_source)
    for curve_spec in profile.curves.values():
        _check_pinned_file(root, curve_spec.poseidon_constants_json)
        if curve_spec.poseidon_circom_constants is not None:
            _check_pinned_file(root, curve_spec.poseidon_circom_constants)

    for circuit in profile.circuits:
        for src_file in circuit.source_files:
            _check_pinned_file(root, src_file)
        if r1cs_dir is not None:
            r1cs_name = Path(circuit.entry_circuit).stem + ".r1cs"
            actual_sha, _ = _sha256_file(r1cs_dir / r1cs_name)
            if not hmac.compare_digest(actual_sha, circuit.r1cs_sha256):
                raise ProfileValidationError(f"r1cs_hash_drift:{circuit.circuit_id}")

    return profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the frozen pre-audit circuit profile manifest.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path, default=PREAUDIT_MANIFEST_PATH)
    parser.add_argument("--trusted-digest", default=None)
    parser.add_argument("--r1cs-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        profile = validate_preaudit_profile(
            args.root,
            args.manifest,
            trusted_digest=args.trusted_digest,
            r1cs_dir=args.r1cs_dir,
        )
    except ProfileValidationError as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc), "production_eligible": False}))
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "profile_id": profile.profile_id,
                "assurance": profile.assurance,
                "manifest_digest": profile.digest,
                "circuits": [c.circuit_id for c in profile.circuits],
                "production_eligible": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
