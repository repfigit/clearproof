"""
Integration tests for gRPC TRISA Bridge — verifies wire-format SecureEnvelope roundtrip.

These tests verify that the SecureEnvelopeBuilder produces valid TRISA wire format
that can be parsed and verified using the official protobuf definitions.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.protocol.bridges import trisa_api_pb2 as pb2
from src.protocol.bridges import trisa_errors_pb2 as errors_pb2
from src.protocol.bridges.grpc_trisa_bridge import (
    SecureEnvelopeBuilder,
    TRISAError,
)
from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload


@pytest.fixture
def rsa_keypair():
    """Generate an RSA key pair for testing TRISA key wrapping."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key_der


@pytest.fixture
def originator_keypair(rsa_keypair):
    """Generate an originator signing key pair."""
    return rsa_keypair


class TestSecureEnvelopeBuilder:
    """Tests for SecureEnvelopeBuilder wire format compliance."""

    def test_envelope_fields_match_proto(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Envelope has all required proto fields."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Verify all proto3 required fields are present with correct values
        assert envelope.id == sample_compliance_proof.transfer_id
        assert len(envelope.payload) > 0
        assert len(envelope.encryption_key) > 0
        assert envelope.encryption_algorithm == "AES-256-GCM"
        assert len(envelope.hmac) == 32  # SHA256 output
        assert len(envelope.hmac_secret) > 0
        assert envelope.hmac_algorithm == "HMAC-SHA256"
        assert envelope.sealed is True
        assert len(envelope.timestamp) > 0  # ISO-8601 timestamp string
        assert envelope.transfer_state == pb2.STARTED

    def test_envelope_roundtrip_decryption(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Encrypted envelope can be decrypted by the beneficiary."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Parse and decrypt
        payload = builder.parse_envelope(envelope, private_key)

        # Verify payload structure
        assert "zk_compliance_proof" in payload
        assert "encrypted_pii" in payload
        assert "pii_nonce" in payload
        assert payload["payload_version"] == "1.0"

        # Verify compliance proof data
        proof = payload["zk_compliance_proof"]
        assert proof["proof_id"] == sample_compliance_proof.proof_id
        assert proof["jurisdiction"] == sample_compliance_proof.jurisdiction

    def test_hmac_verification(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """HMAC is correctly computed and verifiable."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Unwrap HMAC secret
        hmac_secret = private_key.decrypt(
            envelope.hmac_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Recompute HMAC
        computed_hmac = builder.compute_hmac(envelope.payload, hmac_secret)

        assert computed_hmac == envelope.hmac

    def test_tamper_detection(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Tampered payload fails HMAC verification."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Tamper with the payload
        tampered_payload = envelope.payload[:-1] + bytes([envelope.payload[-1] ^ 0xFF])
        tampered_envelope = pb2.SecureEnvelope(
            id=envelope.id,
            payload=tampered_payload,
            encryption_key=envelope.encryption_key,
            encryption_algorithm=envelope.encryption_algorithm,
            hmac=envelope.hmac,
            hmac_secret=envelope.hmac_secret,
            hmac_algorithm=envelope.hmac_algorithm,
            sealed=envelope.sealed,
            timestamp=envelope.timestamp,
            transfer_state=envelope.transfer_state,
        )

        with pytest.raises(TRISAError) as exc_info:
            builder.parse_envelope(tampered_envelope, private_key)

        assert exc_info.value.code == errors_pb2.Error.INVALID_SIGNATURE

    def test_wrapped_key_format(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Wrapped encryption key is valid RSA-OAEP ciphertext."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Decrypt the wrapped key
        aes_key = private_key.decrypt(
            envelope.encryption_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        assert len(aes_key) == 32  # AES-256

    def test_payload_format(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Inner payload is valid JSON with required fields."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=sample_compliance_proof.transfer_id,
            compliance_proof=sample_compliance_proof,
            hybrid_payload=sample_hybrid_payload,
        )

        # Parse the envelope
        payload = builder.parse_envelope(envelope, private_key)

        # Verify JSON structure
        assert isinstance(payload, dict)
        assert "zk_compliance_proof" in payload
        assert "encrypted_pii" in payload
        assert "pii_nonce" in payload
        assert "pii_associated_data" in payload
        assert "ivms101_version" in payload
        assert "payload_version" in payload

        # Verify base64 encoding
        decoded_pii = base64.b64decode(payload["encrypted_pii"])
        assert len(decoded_pii) > 0

    def test_transfer_state_values(
        self,
        sample_compliance_proof: ComplianceProof,
        sample_hybrid_payload: HybridPayload,
        rsa_keypair,
    ):
        """Envelope supports all valid TransferState values."""
        private_key, beneficiary_public_key = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=beneficiary_public_key,
            originator_signing_key=b"test-signing-key",
        )

        for state in [pb2.STARTED, pb2.PENDING, pb2.ACCEPTED, pb2.COMPLETED, pb2.REJECTED]:
            envelope = builder.build_envelope(
                transfer_id=sample_compliance_proof.transfer_id,
                compliance_proof=sample_compliance_proof,
                hybrid_payload=sample_hybrid_payload,
                transfer_state=state,
            )
            assert envelope.transfer_state == state


class TestTRISAError:
    """Tests for TRISAError exception handling."""

    def test_from_pb2(self):
        """TRISAError can be created from protobuf Error."""
        error = errors_pb2.Error(
            code=errors_pb2.Error.UNKNOWN_WALLET_ADDRESS,
            message="Wallet address not found",
            retry=False,
        )

        trisa_error = TRISAError.from_pb2(error)

        assert trisa_error.code == errors_pb2.Error.UNKNOWN_WALLET_ADDRESS
        assert trisa_error.message == "Wallet address not found"
        assert trisa_error.retry is False

    def test_str_representation(self):
        """TRISAError has a useful string representation."""
        error_code = errors_pb2.Error.COMPLIANCE_CHECK_FAIL
        error = TRISAError(
            code=error_code,
            message="Sanctions match found",
            retry=False,
        )

        # String includes the integer error code and message
        assert str(error_code) in str(error)
        assert "Sanctions match found" in str(error)


class TestEnvelopeBuilderDirectUsage:
    """Tests for direct builder usage without fixtures."""

    def test_build_with_minimal_proof(self):
        """Builder works with minimal ComplianceProof."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        proof = ComplianceProof(
            proof_id=str(uuid.uuid4()),
            transfer_id=str(uuid.uuid4()),
            groth16_proof=base64.b64encode(b'{"pi_a":[],"pi_b":[],"pi_c":[]}').decode(),
            public_signals=[
                "1",
                "0",
                "0",
                "0",
                "2",
                str(int(time.time())),
                "21843",
                "0",
                "25000",
                "300000",
                "1000000",
                "0",
                "0",
                "0",
                "0",
                str(int(time.time()) + 300),
            ],
            verification_key=base64.b64encode(b'{"vk_alpha_1":[]}').decode(),
            originator_vasp_did="did:web:test.example.com",
            beneficiary_vasp_did="did:web:beneficiary.example.com",
            jurisdiction="US",
            amount_tier=2,
            proof_generated_at=int(time.time()),
            proof_expires_at=int(time.time()) + 300,
        )

        payload = HybridPayload(
            compliance_proof=proof,
            encrypted_pii=b"encrypted-pii-data",
            encryption_algorithm="AES-256-GCM",
            pii_nonce=b"123456789012",  # 12 bytes
            pii_associated_data="test-envelope",
        )

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=public_key,
            originator_signing_key=b"test-signing-key",
        )

        envelope = builder.build_envelope(
            transfer_id=proof.transfer_id,
            compliance_proof=proof,
            hybrid_payload=payload,
        )

        assert envelope.id == proof.transfer_id
        assert envelope.sealed is True

        # Roundtrip
        parsed = builder.parse_envelope(envelope, private_key)
        assert "zk_compliance_proof" in parsed


class TestUnsealedEnvelope:
    """Tests for parse_envelope with sealed=False path (M6)."""

    def test_parse_unsealed_envelope(self, rsa_keypair):
        """Unsealed envelope payload is parsed as raw JSON without decryption."""
        private_key, public_key_der = rsa_keypair

        builder = SecureEnvelopeBuilder(
            beneficiary_public_key=public_key_der,
            originator_signing_key=b"test-signing-key",
        )

        raw_payload = {"test_key": "test_value", "number": 42}
        envelope = pb2.SecureEnvelope(
            id="test-unsealed",
            payload=json.dumps(raw_payload).encode("utf-8"),
            sealed=False,
            timestamp="2025-01-01T00:00:00Z",
            transfer_state=pb2.STARTED,
        )

        parsed = builder.parse_envelope(envelope, private_key)
        assert parsed == raw_payload


async def test_server_errors_do_not_log_decrypted_data(rsa_keypair, monkeypatch, caplog):
    from src.protocol.bridges.grpc_trisa_bridge import TRISAServer

    private, public = rsa_keypair
    server = TRISAServer(private, public, b"synthetic")

    async def handler(payload, request):
        raise ValueError("synthetic-private-marker")

    monkeypatch.setattr(server, "handle_transfer", handler)
    response = await server.Transfer(pb2.SecureEnvelope(id="synthetic-private-id", payload=b"{}"), None)
    assert response.error.code == errors_pb2.Error.INTERNAL_ERROR
    assert response.error.message == "Internal server error"
    assert "synthetic-private-marker" not in caplog.text
    assert "synthetic-private-id" not in caplog.text


async def test_server_protocol_errors_and_stream_preserve_request_binding(rsa_keypair, monkeypatch):
    from src.protocol.bridges.grpc_trisa_bridge import TRISAServer

    private, public = rsa_keypair
    server = TRISAServer(private, public, b"synthetic")
    request = pb2.SecureEnvelope(id="first", payload=b"{}")
    accepted = await server.Transfer(request, None)
    assert accepted.id == request.id
    assert accepted.transfer_state == pb2.ACCEPTED
    assert accepted.timestamp

    async def handler(payload, request):
        raise TRISAError(errors_pb2.Error.COMPLIANCE_CHECK_FAIL, "Rejected", retry=False)

    monkeypatch.setattr(server, "handle_transfer", handler)

    async def requests():
        yield request
        yield pb2.SecureEnvelope(id="second", payload=b"{}")

    responses = [response async for response in server.TransferStream(requests(), None)]
    assert [response.id for response in responses] == ["first", "second"]
    assert all(response.error.code == errors_pb2.Error.COMPLIANCE_CHECK_FAIL for response in responses)
    assert all(not response.error.retry for response in responses)
    key = await server.KeyExchange(pb2.SigningKey(), None)
    assert key.data == public
    assert key.signature_algorithm == "RSA-SHA256"


async def test_client_rpc_routing_errors_and_channel_cleanup(monkeypatch, caplog):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from src.protocol.bridges import grpc_trisa_bridge as module

    channel = SimpleNamespace(close=AsyncMock())
    response = pb2.SecureEnvelope(id="reply")
    stub = SimpleNamespace(
        Transfer=AsyncMock(return_value=response), ConfirmAddress=AsyncMock(), KeyExchange=AsyncMock()
    )
    secure = Mock(return_value=channel)
    monkeypatch.setattr(module.grpc.aio, "secure_channel", secure)
    monkeypatch.setattr(module.pb2_grpc, "TRISANetworkStub", Mock(return_value=stub))
    request = pb2.SecureEnvelope(id="request")
    async with module.TRISAClient("localhost:1") as client:
        assert "server-only TLS" in caplog.text
        assert await client.transfer(request, timeout=2) == response
        stub.Transfer.assert_awaited_once_with(request, timeout=2)
        await client.confirm_address("0x123", "ethereum", pb2.KEYTOKEN)
        address = stub.ConfirmAddress.await_args.args[0]
        assert (address.crypto_address, address.network, address.confirmation) == ("0x123", "ethereum", pb2.KEYTOKEN)
        key = pb2.SigningKey(version=1)
        await client.key_exchange(key)
        stub.KeyExchange.assert_awaited_once_with(key)
        stub.Transfer.return_value = pb2.SecureEnvelope(
            error=errors_pb2.Error(code=errors_pb2.Error.COMPLIANCE_CHECK_FAIL, message="Rejected", retry=False)
        )
        with pytest.raises(TRISAError) as error:
            await client.transfer(request)
        assert not error.value.retry
    channel.close.assert_awaited_once()
    credentials = module.grpc.ssl_channel_credentials()
    module.TRISAClient("localhost:1", credentials)
    assert secure.call_args.args == ("localhost:1", credentials)


async def test_client_stream_stops_at_protocol_error(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from src.protocol.bridges import grpc_trisa_bridge as module

    seen = []

    async def stream(requests, timeout):
        assert timeout == 3
        async for request in requests:
            seen.append(request.id)
            yield pb2.SecureEnvelope(id=request.id)
            yield pb2.SecureEnvelope(error=errors_pb2.Error(code=errors_pb2.Error.INTERNAL_ERROR, message="Failed"))
            pytest.fail("client consumed beyond protocol error")

    monkeypatch.setattr(module.grpc.aio, "secure_channel", Mock(return_value=SimpleNamespace(close=AsyncMock())))
    monkeypatch.setattr(module.pb2_grpc, "TRISANetworkStub", Mock(return_value=SimpleNamespace(TransferStream=stream)))

    async def requests():
        yield pb2.SecureEnvelope(id="first")

    async with module.TRISAClient("localhost:1") as client:
        output = client.transfer_stream(requests(), timeout=3)
        assert (await anext(output)).id == "first"
        with pytest.raises(TRISAError):
            await anext(output)
    assert seen == ["first"]


@pytest.mark.parametrize("mtls", [False, True])
async def test_factory_serves_real_tls_rpcs(
    rsa_keypair, tmp_path, monkeypatch, mtls, sample_compliance_proof, sample_hybrid_payload
):
    from datetime import datetime, timedelta, timezone

    import grpc
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    from src.protocol.bridges import grpc_trisa_bridge as module

    private, public = rsa_keypair
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    key_path, cert_path = tmp_path / "key.pem", tmp_path / "cert.pem"
    key_path.write_bytes(pem)
    cert_path.write_bytes(cert)
    if mtls:
        with pytest.raises(ValueError, match="trusted_ca_path is required"):
            await module.create_trisa_server(str(key_path), str(cert_path), port=0)
    real_factory = grpc.aio.server
    ports = []

    def factory(*args, **kwargs):
        server = real_factory(*args, **kwargs)
        original_bind = server.add_secure_port

        def bind(address, credentials):
            port = original_bind(address, credentials)
            ports.append(port)
            return port

        monkeypatch.setattr(server, "add_secure_port", bind)
        return server

    monkeypatch.setattr(grpc.aio, "server", factory)
    server = await module.create_trisa_server(
        str(key_path), str(cert_path), port=0, require_mtls=mtls, trusted_ca_path=str(cert_path) if mtls else None
    )
    await server.start()
    credentials = grpc.ssl_channel_credentials(
        root_certificates=cert, private_key=pem if mtls else None, certificate_chain=cert if mtls else None
    )
    try:
        if mtls:
            unauthenticated = grpc.ssl_channel_credentials(root_certificates=cert)
            async with module.TRISAClient(f"localhost:{ports[0]}", unauthenticated) as client:
                with pytest.raises(grpc.aio.AioRpcError) as error:
                    await client.transfer(pb2.SecureEnvelope(payload=b"{}"), timeout=2)
                assert error.value.code() in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED)
        async with module.TRISAClient(f"localhost:{ports[0]}", credentials) as client:
            builder = module.SecureEnvelopeBuilder(public, b"synthetic")
            request = builder.build_envelope("tls-transfer", sample_compliance_proof, sample_hybrid_payload)
            result = await client.transfer(request, timeout=5)
            assert result.id == request.id
            assert result.transfer_state == pb2.ACCEPTED

            async def requests():
                yield request

            streamed = [item async for item in client.transfer_stream(requests(), timeout=5)]
            assert [item.id for item in streamed] == [request.id]
            assert (await client.key_exchange(pb2.SigningKey())).data == public
            with pytest.raises(grpc.aio.AioRpcError) as error:
                await client.confirm_address("0x123", "ethereum")
            assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
    finally:
        await server.stop(0)
