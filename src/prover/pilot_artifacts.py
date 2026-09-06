"""Pinned development artifact inspection. No downloads, proving or authorization."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from src.policy.model import POLICY_SCHEMA_DIGEST
from src.protocol.canonical import record_digest
from src.protocol.transfer import Hex32, Record, VerificationContext
from src.prover.pilot_compliance import PUBLIC_SIGNALS

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


class ArtifactError(ValueError):
    """Stable diagnostic code; never includes file contents or customer input."""


def strict_json(raw: bytes, *, limit: int = 65536):
    if len(raw) > limit:
        raise ArtifactError("json_size_limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ArtifactError("duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ArtifactError("invalid_json_constant")

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError("invalid_json") from None


class ArtifactFile(Record):
    filename: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
    sha256: Hex32
    size: int = Field(ge=1, le=MAX_ARTIFACT_BYTES)


class PilotArtifactManifest(Record):
    schema_version: Literal["clearproof-artifact-manifest-v1"] = "clearproof-artifact-manifest-v1"
    proof_profile: Literal["pilot-transfer-v1"] = "pilot-transfer-v1"
    protocol: Literal["groth16"] = "groth16"
    curve: Literal["bn128"] = "bn128"
    assurance: Literal["development-unapproved"] = "development-unapproved"
    transfer_schema: Literal["clearproof-transfer-v1"] = "clearproof-transfer-v1"
    context_schema: Literal["clearproof-verification-context-v1"] = "clearproof-verification-context-v1"
    policy_schema_digest: Hex32
    source_bundle_digest: Hex32
    compiler_sha256: Hex32
    public_signals: tuple[str, ...]
    wasm: ArtifactFile
    r1cs: ArtifactFile
    proving_key: ArtifactFile
    verification_key: ArtifactFile

    @field_validator("public_signals")
    @classmethod
    def exact_layout(cls, value):
        if value != PUBLIC_SIGNALS:
            raise ValueError("Unsupported signal layout")
        return value

    @model_validator(mode="after")
    def separate_files(self):
        names = [getattr(self, role).filename for role in ARTIFACT_ROLES]
        if len(set(names)) != len(names):
            raise ValueError("Artifact files must be distinct")
        return self

    @property
    def digest(self) -> str:
        return record_digest("clearproof/artifact-manifest/v1", self.model_dump(mode="json"))


ARTIFACT_ROLES = ("wasm", "r1cs", "proving_key", "verification_key")


@dataclass(frozen=True)
class InspectedArtifacts:
    manifest: PilotArtifactManifest = field(repr=False)
    verification_key_bytes: bytes = field(repr=False)

    def check_artifact_context(self, context: VerificationContext) -> None:
        """Only artifact/profile binding; not transfer or state authorization."""
        context = VerificationContext.model_validate(context)
        if (context.artifact_manifest_digest, context.proof_profile) != (
            self.manifest.digest,
            self.manifest.proof_profile,
        ):
            raise ArtifactError("artifact_context_mismatch")
        if self.manifest.policy_schema_digest != POLICY_SCHEMA_DIGEST:
            raise ArtifactError("unsupported_policy_schema")

    def report(self) -> dict:
        return {
            "status": "development_unapproved",
            "manifest_digest": self.manifest.digest,
            "proof_profile": self.manifest.proof_profile,
            "checked_artifacts": list(ARTIFACT_ROLES),
            "production_eligible": False,
            "policy_schema_supported": self.manifest.policy_schema_digest == POLICY_SCHEMA_DIGEST,
        }


def _read_file(directory: int, filename: str, *, limit: int, expected: ArtifactFile | None = None) -> bytes:
    """Open one regular basename without following symlinks; hash the opened FD."""
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                raise ArtifactError("invalid_artifact_file")
            if expected and before.st_size != expected.size:
                raise ArtifactError("artifact_size_mismatch")
            digest = hashlib.sha256()
            captured = bytearray()
            read = 0
            while chunk := stream.read(min(1024 * 1024, limit + 1 - read)):
                read += len(chunk)
                if read > limit:
                    raise ArtifactError("artifact_size_limit")
                digest.update(chunk)
                # Only the small manifest/key is returned; no whole zkey in RAM.
                if limit <= 65536:
                    captured.extend(chunk)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or read != before.st_size:
                raise ArtifactError("artifact_changed_during_read")
            if expected and not hmac.compare_digest(digest.hexdigest(), expected.sha256):
                raise ArtifactError("artifact_hash_mismatch")
            return bytes(captured)
    except OSError:
        raise ArtifactError("artifact_unavailable") from None


def inspect_artifacts(root: Path, *, trusted_digest: str, mode: str = "development") -> InspectedArtifacts:
    """The pin must come from operator configuration, never from the proof bundle.

    This checks exact files, not ceremony legitimacy or source-to-binary
    reproducibility. Only the returned verification key is a validated snapshot;
    callers must not reopen a previously checked path and assume it is unchanged.
    """
    if mode not in ("development", "production"):
        raise ArtifactError("invalid_runtime_mode")
    if type(trusted_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", trusted_digest):
        raise ArtifactError("invalid_trust_pin")
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ArtifactError("artifact_directory_unavailable") from None
    try:
        raw = _read_file(directory, "manifest.json", limit=65536)
        try:
            # JSON arrays deliberately become tuples only through JSON validation.
            strict_json(raw)
            manifest = PilotArtifactManifest.model_validate_json(raw)
        except ValueError:
            raise ArtifactError("invalid_manifest") from None
        if not hmac.compare_digest(manifest.digest, trusted_digest):
            raise ArtifactError("untrusted_manifest")
        if mode == "production":
            raise ArtifactError("development_artifacts_forbidden")
        key = b""
        for role in ARTIFACT_ROLES:
            entry = getattr(manifest, role)
            data = _read_file(
                directory,
                entry.filename,
                limit=65536 if role == "verification_key" else MAX_ARTIFACT_BYTES,
                expected=entry,
            )
            if role == "verification_key":
                key = data
        value = strict_json(key)
        if (
            type(value) is not dict
            or value.get("protocol") != "groth16"
            or value.get("curve") != "bn128"
            or type(value.get("nPublic")) is not int
            or value["nPublic"] != 8
            or type(value.get("IC")) is not list
            or len(value["IC"]) != 9
        ):
            raise ArtifactError("verification_key_profile_mismatch")
        return InspectedArtifacts(manifest, key)
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only development artifact doctor; no network or proving")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--trusted-manifest-digest", required=True)
    parser.add_argument("--mode", choices=("development", "production"), default="development")
    args = parser.parse_args()
    try:
        result = inspect_artifacts(args.directory, trusted_digest=args.trusted_manifest_digest, mode=args.mode)
    except ArtifactError as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc), "production_eligible": False}))
        return 1
    print(json.dumps(result.report()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
