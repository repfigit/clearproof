"""Fresh-process pilot reviewer. All trust is supplied separately from the bundle."""

import asyncio
import json
import socket
import sys
from pathlib import Path

from cryptography import x509

from src.policy.fact_approval import FactAuthority, FactTrustStore
from src.policy.model import PilotPolicy, PolicyTrustStore
from src.protocol.decision_attestation import DecisionAuthority, DecisionTrustStore
from src.protocol.information_approval import InformationAuthority, InformationTrustStore
from src.protocol.root_snapshot import RootAuthority, RootTrustStore
from src.protocol.valuation_approval import ValuationAuthority, ValuationTrustStore
from src.prover.history import inspect_history_bundle
from src.prover.history_statement import HistoryStatementTrust
from src.prover.history_status import HistoryStatusAuthority, HistoryStatusTrust
from src.prover.history_timing import TimestampTrust
from src.prover.pilot_artifacts import inspect_artifacts
from src.prover.pilot_roots import CurrentRootPins
from src.prover.pilot_verifier import PilotPairingVerifier
from src.services.evidence_export import open_evidence_bundle


def no_network(*args, **kwargs):
    raise RuntimeError("Network forbidden during offline review")


def main():
    socket.socket.connect = no_network
    v = json.load(sys.stdin)
    trust = v["trust"]

    def model(cls, value):
        return cls.model_validate_json(json.dumps(value))

    policy = model(PilotPolicy, trust["policy"])
    statements = HistoryStatementTrust(
        policy_trust=PolicyTrustStore([policy], current_digests=(policy.digest,)),
        root_pins=model(CurrentRootPins, trust["root_pins"]),
        root_trust=RootTrustStore([model(RootAuthority, a) for a in trust["roots"]]),
        valuation_trust=ValuationTrustStore([model(ValuationAuthority, a) for a in trust["valuations"]]),
    )
    timing = TimestampTrust(
        certificate=x509.load_der_x509_certificate(bytes.fromhex(v["tsa_leaf"])),
        roots=(x509.load_der_x509_certificate(bytes.fromhex(v["tsa_root"])),),
        **v["timing_config"],
    )
    bundle = open_evidence_bundle(v["encrypted"].encode(), bytes.fromhex(v["key"]), expected_binding=v["binding"])
    artifacts = inspect_artifacts(Path(v["artifacts"]), trusted_digest=v["pin"])
    verifier = PilotPairingVerifier.load(
        artifacts,
        bundle_path=Path(v["runtime"]),
        bundle_sha256=v["runtime_pin"],
        node=Path(v["node"]),
    )
    report = asyncio.run(
        inspect_history_bundle(
            bundle,
            verifier,
            statement_trust=statements,
            timing_trust=timing,
            fact_trust=FactTrustStore([model(FactAuthority, trust["facts"])]),
            decision_trust=DecisionTrustStore([model(DecisionAuthority, trust["decision"])]),
            status_trust=HistoryStatusTrust([model(HistoryStatusAuthority, trust["status"])]),
            information_trust=InformationTrustStore([model(InformationAuthority, trust["information"])]),
            **v["history_args"],
        )
    )
    print(
        json.dumps(
            {
                "receipt_id": bundle["receipt_id"],
                "records": len(bundle["records"]),
                "integrity": report.integrity_valid,
                "pairing": report.cryptographic_valid,
                "timing": report.timing_authenticated,
                "outcome": report.outcome,
            }
        )
    )


if __name__ == "__main__":
    main()
