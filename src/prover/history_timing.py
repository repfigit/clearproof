"""Offline RFC 3161 evidence of existence, with independently pinned TSA authority."""

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from rfc3161_client import HashAlgorithm, TimestampRequestBuilder, VerifierBuilder, decode_timestamp_response
from rfc3161_client.errors import VerificationError

from src.protocol.decision_attestation import SignedDecision

MAX_TIMESTAMP_BYTES = 32768
_SHA256 = x509.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
_ALLOWED_DIGESTS = {
    _SHA256,
    x509.ObjectIdentifier("2.16.840.1.101.3.4.2.2"),
    x509.ObjectIdentifier("2.16.840.1.101.3.4.2.3"),
}


def timestamp_message(signed: SignedDecision) -> bytes:
    return b"clearproof/decision-timestamp/v1\0" + SignedDecision.model_validate(signed).canonical_bytes()


def timestamp_request(signed: SignedDecision) -> bytes:
    """Only a digest and random nonce enter the DER request. No network or file I/O."""
    return (
        TimestampRequestBuilder()
        .data(timestamp_message(signed))
        .hash_algorithm(HashAlgorithm.SHA256)
        .build()
        .as_bytes()
    )


def _microseconds(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("Timestamp must have a UTC offset")
    delta = value - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


@dataclass(frozen=True)
class TimestampObservation:
    generated_at_us: int
    accuracy_us: int
    tsa_certificate_sha256: str
    policy_oid: str

    @property
    def earliest_us(self):
        return self.generated_at_us - self.accuracy_us

    @property
    def latest_us(self):
        return self.generated_at_us + self.accuracy_us


class TimestampTrust:
    def __init__(
        self,
        *,
        certificate: x509.Certificate,
        roots: tuple[x509.Certificate, ...],
        policy_oid: str,
        not_before: int,
        not_after: int,
        max_accuracy_us: int = 1000000,
        max_delay_seconds: int = 300,
        compromised_at: int | None = None,
    ):
        if (
            type(not_before) is not int
            or type(not_after) is not int
            or not 0 <= not_before < not_after < 2**53
            or type(max_accuracy_us) is not int
            or not 0 <= max_accuracy_us <= 60000000
            or type(max_delay_seconds) is not int
            or not 1 <= max_delay_seconds <= 3600
            or (compromised_at is not None and (type(compromised_at) is not int or not 0 <= compromised_at < 2**53))
            or not 1 <= len(roots) <= 16
        ):
            raise ValueError("Invalid timestamp authority configuration")
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if not eku.critical or list(eku.value) != [x509.ExtendedKeyUsageOID.TIME_STAMPING]:
            raise ValueError("TSA requires exclusive critical timestamping usage")
        builder = VerifierBuilder().tsa_certificate(certificate).policy_id(x509.ObjectIdentifier(policy_oid))
        for root in roots:
            builder = builder.add_root_certificate(root)
        self._verifier = builder.build()
        self._certificate = certificate
        self._not_before, self._not_after = not_before, not_after
        self._max_accuracy_us, self.max_delay_seconds = max_accuracy_us, max_delay_seconds
        self._compromised_at = compromised_at

    def verify(self, raw: bytes, signed: SignedDecision, *, verified_at: int) -> TimestampObservation:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_TIMESTAMP_BYTES:
            raise ValueError("Invalid timestamp response size")
        if type(verified_at) is not int or not 0 <= verified_at < 2**53:
            raise ValueError("Invalid timestamp review time")
        if self._compromised_at is not None and self._compromised_at <= verified_at:
            raise ValueError("Timestamp authority compromise is unresolved")
        try:
            response = decode_timestamp_response(raw)
            info = response.tst_info
            if (
                response.as_bytes() != raw
                or info.version != 1
                or info.message_imprint.hash_algorithm != _SHA256
                or not response.signed_data.digest_algorithms
                or not response.signed_data.digest_algorithms <= _ALLOWED_DIGESTS
            ):
                raise ValueError("Unsupported timestamp response profile")
            self._verifier.verify_message(response, timestamp_message(signed))
            accuracy = info.accuracy
            if accuracy is None:
                raise ValueError("Timestamp accuracy is unspecified")
            seconds, millis, micros = accuracy.seconds or 0, accuracy.millis or 0, accuracy.micros or 0
            if seconds < 0 or not 0 <= millis <= 999 or not 0 <= micros <= 999:
                raise ValueError("Invalid timestamp accuracy")
            observation = TimestampObservation(
                _microseconds(info.gen_time),
                seconds * 1000000 + millis * 1000 + micros,
                self._certificate.fingerprint(hashes.SHA256()).hex(),
                info.policy.dotted_string,
            )
        except (VerificationError, ValueError, TypeError, OverflowError) as exc:
            raise ValueError("Timestamp response could not be authenticated") from exc
        if (
            observation.accuracy_us > self._max_accuracy_us
            or observation.earliest_us < self._not_before * 1000000
            or observation.latest_us >= self._not_after * 1000000
            or observation.latest_us > verified_at * 1000000
        ):
            raise ValueError("Timestamp observation is outside approved bounds")
        return observation

    def verify_decision_window(self, raw: bytes, signed: SignedDecision, *, expires_at: int, verified_at: int):
        observation = self.verify(raw, signed, verified_at=verified_at)
        decision_at = signed.statement.decision_at
        if (
            type(expires_at) is not int
            or not decision_at < expires_at < 2**53
            or observation.earliest_us < decision_at * 1000000
            or observation.latest_us > (decision_at + self.max_delay_seconds) * 1000000
            or observation.latest_us >= expires_at * 1000000
        ):
            raise ValueError("Timestamp does not bound the claimed decision within its permitted window")
        return observation
