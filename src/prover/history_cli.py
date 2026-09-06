"""Offline history CLI: independent trust, stdin key, minimized JSON output."""

import argparse
import asyncio
import base64
import json
import os
import re
import stat
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from cryptography import x509
from pydantic import Field

from src.policy.fact_approval import FactAuthority, FactTrustStore
from src.policy.model import PilotPolicy, PolicyTrustStore
from src.protocol.decision_attestation import DecisionAuthority, DecisionTrustStore
from src.protocol.information_approval import InformationAuthority, InformationTrustStore
from src.protocol.root_snapshot import RootAuthority, RootTrustStore
from src.protocol.transfer import Epoch, Hex32, OpaqueId, Record
from src.protocol.valuation_approval import ValuationAuthority, ValuationTrustStore
from src.prover.history import inspect_history_bundle
from src.prover.history_statement import HistoryStatementTrust
from src.prover.history_status import HistoryStatusAuthority, HistoryStatusTrust
from src.prover.history_timing import TimestampTrust
from src.prover.pilot_artifacts import inspect_artifacts, strict_json
from src.prover.pilot_roots import CurrentRootPins
from src.prover.pilot_verifier import PilotPairingVerifier
from src.services.evidence_export import open_evidence_bundle


class ExportBinding(Record):
    tenant_id: OpaqueId
    receipt_id: Hex32
    reviewer_id: OpaqueId
    key_id: str = Field(min_length=1, max_length=128)
    exported_at: Epoch


class StatementConfiguration(Record):
    policies: tuple[PilotPolicy, ...] = Field(min_length=1, max_length=256)
    policy_pins: tuple[Hex32, ...] = Field(min_length=1, max_length=256)
    root_pins: CurrentRootPins
    roots: tuple[RootAuthority, ...] = Field(min_length=1, max_length=256)
    valuations: tuple[ValuationAuthority, ...] = Field(min_length=1, max_length=256)


class TimingConfiguration(Record):
    certificate_der_base64: str = Field(min_length=1, max_length=21848)
    roots_der_base64: tuple[str, ...] = Field(min_length=1, max_length=16)
    policy_oid: str = Field(min_length=3, max_length=128)
    not_before: Epoch
    not_after: Epoch
    max_accuracy_us: int = Field(default=1000000, ge=0, le=60000000)
    max_delay_seconds: int = Field(default=300, ge=1, le=3600)
    compromised_at: Epoch | None = None

    def trust(self):
        def certificate(raw):
            if not 1 <= len(raw) <= 21848:
                raise ValueError("Certificate size limit")
            return x509.load_der_x509_certificate(base64.b64decode(raw, validate=True))

        return TimestampTrust(
            certificate=certificate(self.certificate_der_base64),
            roots=tuple(certificate(raw) for raw in self.roots_der_base64),
            **self.model_dump(exclude={"certificate_der_base64", "roots_der_base64"}),
        )


class HistoryReviewerConfiguration(Record):
    schema_version: Literal["clearproof-history-reviewer-v1"] = "clearproof-history-reviewer-v1"
    binding: ExportBinding
    artifact_manifest_digest: Hex32
    runtime_sha256: Hex32
    statement: StatementConfiguration | None = None
    facts: tuple[FactAuthority, ...] = Field(default=(), max_length=256)
    decisions: tuple[DecisionAuthority, ...] = Field(default=(), max_length=256)
    statuses: tuple[HistoryStatusAuthority, ...] = Field(default=(), max_length=256)
    information: tuple[InformationAuthority, ...] = Field(default=(), max_length=256)
    timing: TimingConfiguration | None = None

    def trust(self):
        values = {}
        if self.statement is not None:
            config = self.statement
            values["statement_trust"] = HistoryStatementTrust(
                policy_trust=PolicyTrustStore(list(config.policies), current_digests=config.policy_pins),
                root_pins=config.root_pins,
                root_trust=RootTrustStore(list(config.roots)),
                valuation_trust=ValuationTrustStore(list(config.valuations)),
            )
        for name, field, cls in (
            ("fact_trust", self.facts, FactTrustStore),
            ("decision_trust", self.decisions, DecisionTrustStore),
            ("status_trust", self.statuses, HistoryStatusTrust),
            ("information_trust", self.information, InformationTrustStore),
        ):
            if field:
                values[name] = cls(list(field))
        if self.timing is not None:
            values["timing_trust"] = self.timing.trust()
        return values


def read_bounded(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular input file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input size limit")
    return raw


def load_reviewer_configuration(raw: bytes):
    parsed = strict_json(raw, limit=256 * 1024)
    return HistoryReviewerConfiguration.model_validate_json(json.dumps(parsed))


async def review(args, private_key: bytes):
    config = load_reviewer_configuration(read_bounded(args.trust, 256 * 1024))
    trust = config.trust()
    artifacts = inspect_artifacts(args.artifacts, trusted_digest=config.artifact_manifest_digest)
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=args.runtime,
        bundle_sha256=config.runtime_sha256,
        node=args.node,
    )
    bundle = open_evidence_bundle(
        read_bounded(args.bundle, 12 * 1024 * 1024),
        private_key,
        expected_binding=config.binding.model_dump(mode="json"),
    )
    result = await inspect_history_bundle(
        bundle,
        verifier,
        expected_receipt_id=config.binding.receipt_id,
        expected_tenant=config.binding.tenant_id,
        verified_at=args.verified_at,
        **trust,
    )
    return {
        "schema_version": "clearproof-history-report-v1",
        "scope": "recorded-local-policy-decision",
        "assurance": artifacts.manifest.assurance,
        "receipt_id": config.binding.receipt_id,
        **asdict(result),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Review encrypted pilot history offline; read a 64-hex reviewer key on stdin"
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path, help="Independently approved reviewer configuration")
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path, help="Pinned snarkjs JavaScript bundle")
    parser.add_argument("--node", required=True, type=Path, help="Trusted Node executable")
    parser.add_argument("--verified-at", type=int, default=int(time.time()))
    args = parser.parse_args(argv)
    try:
        key = sys.stdin.buffer.read(67)
        if not re.fullmatch(rb"[0-9a-f]{64}(?:\r?\n)?", key):
            raise ValueError("Invalid reviewer key")
        report = asyncio.run(review(args, bytes.fromhex(key.decode("ascii").strip())))
    except (ValueError, OSError, TypeError, KeyError, RuntimeError):
        report = {
            "schema_version": "clearproof-history-report-v1",
            "scope": "recorded-local-policy-decision",
            "outcome": "indeterminate",
            "reasons": ["history_input_unavailable"],
        }
    print(json.dumps(report, sort_keys=True))
    return {"supported": 0, "contradicted": 1, "indeterminate": 2}[report["outcome"]]


if __name__ == "__main__":
    raise SystemExit(main())
