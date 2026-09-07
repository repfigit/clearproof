"""Local bilateral disposition command with independently supplied trust and stdin keys."""

import argparse
import json
import sys
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from src.protocol.bridges.pilot_bilateral import LocalBilateralCounterparty
from src.protocol.decision_attestation import DecisionAuthority, DecisionTrustStore
from src.protocol.file_input import read_bounded
from src.protocol.information_approval import InformationAuthority, InformationTrustStore
from src.protocol.transfer import Hex32, Record, Transfer, VerificationContext
from src.prover.pilot_artifacts import strict_json
from src.sar.pilot_envelope import RecipientAuthority, RecipientTrustStore


class CounterpartyConfiguration(Record):
    schema_version: Literal["clearproof-local-counterparty-configuration-v1"]
    transfer: Transfer
    context: VerificationContext
    decisions: tuple[DecisionAuthority, ...] = Field(min_length=1, max_length=256)
    information: tuple[InformationAuthority, ...] = Field(min_length=1, max_length=256)
    recipients: tuple[RecipientAuthority, ...] = Field(min_length=1, max_length=256)

    def receiver(self, keys):
        return LocalBilateralCounterparty(
            transfer=self.transfer,
            context=self.context,
            decision_trust=DecisionTrustStore(list(self.decisions)),
            information_trust=InformationTrustStore(list(self.information)),
            recipient_trust=RecipientTrustStore(list(self.recipients)),
            private_keys={key: bytes.fromhex(value) for key, value in keys.items()},
        )


class PrivateKeys(Record):
    keys: dict[Annotated[str, Field(min_length=1, max_length=128)], Hex32] = Field(max_length=256)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--observed-at", required=True, type=int, help="Declared local simulation clock")
    parser.add_argument("--behavior", choices=("accept", "reject", "request-information", "timeout"), default="accept")
    parser.add_argument("--deadline", type=int)
    args = parser.parse_args()
    try:
        config = CounterpartyConfiguration.model_validate_json(
            json.dumps(strict_json(read_bounded(args.trust, 256 * 1024), limit=256 * 1024))
        )
        request = strict_json(read_bounded(args.request, 256 * 1024), limit=256 * 1024)
        keys = PrivateKeys.model_validate_json(json.dumps(strict_json(sys.stdin.buffer.read(65537), limit=65536)))
        result = config.receiver(keys.keys).receive(
            request, now=args.observed_at, behavior=args.behavior, deadline=args.deadline
        )
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        # No source values, filenames, decrypted information or key material in diagnostics.
        print(
            json.dumps(
                dict(
                    schema_version="clearproof-local-counterparty-error-v1",
                    source_authenticity="local-simulator",
                    outcome="invalid-input",
                    reason="invalid-local-message-or-configuration",
                    authorization="not-created",
                    execution="not-requested",
                )
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
