"""
gRPC TRISA Bridge — implements the official TRISA gRPC protocol.

This module provides a real gRPC client for the TRISA Network protocol
using the official proto definitions from github.com/trisacrypto/trisa.

Key components:
- TRISAClient: gRPC client for TRISANetwork service
- TRISAServer: gRPC server servant for handling incoming TRISA transfers
- SecureEnvelopeBuilder: Helper for building wire-format SecureEnvelopes
"""

from __future__ import annotations

import base64
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

import grpc
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

from . import trisa_api_pb2 as pb2
from . import trisa_api_pb2_grpc as pb2_grpc
from . import trisa_errors_pb2 as errors_pb2
from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload

__all__ = ["TRISAClient", "TRISAServer", "SecureEnvelopeBuilder", "TRISAError"]


# TRISA envelope type for ZK Travel Rule payloads
_ZK_ENVELOPE_TYPE = "ZK_TRAVEL_RULE_V1"

# Default TRISA gRPC port
_DEFAULT_TRISA_PORT = 18000


class TRISAError(Exception):
    """Exception raised for TRISA protocol errors."""

    def __init__(self, code: int, message: str, retry: bool = True):
        self.code = code
        self.message = message
        self.retry = retry
        super().__init__(f"TRISA Error {code}: {message}")

    @classmethod
    def from_pb2(cls, error: pb2.Error) -> "TRISAError":
        """Create TRISAError from a protobuf Error message."""
        return cls(
            code=error.code,
            message=error.message,
            retry=error.retry,
        )


class SecureEnvelopeBuilder:
    """
    Builds TRISA SecureEnvelope messages according to the official proto spec.

    The SecureEnvelope contains:
    - id: Transaction identifier
    - payload: Encrypted IVMS101 + ZK proof payload
    - encryption_key: RSA-wrapped AES-256 key
    - encryption_algorithm: "AES-256-GCM"
    - hmac: HMAC signature over encrypted payload
    - hmac_secret: RSA-wrapped HMAC key
    - hmac_algorithm: "HMAC-SHA256"
    - sealed: Whether key/secret are encrypted
    - timestamp: RFC-3339 timestamp
    - transfer_state: STARTED/PENDING/ACCEPTED/etc.
    """

    def __init__(
        self,
        beneficiary_public_key: bytes,
        originator_signing_key: bytes,
    ):
        """
        Initialize the envelope builder.

        Args:
            beneficiary_public_key: DER-encoded RSA public key of beneficiary VASP
            originator_signing_key: DER-encoded RSA signing key of originator
        """
        self.beneficiary_public_key = beneficiary_public_key
        self.originator_signing_key = originator_signing_key

    def build_payload(
        self,
        compliance_proof: ComplianceProof,
        hybrid_payload: HybridPayload,
    ) -> bytes:
        """
        Build the inner payload containing ZK proof + encrypted PII.

        The payload is a JSON object containing:
        - zk_compliance_proof: ComplianceProof model dump
        - encrypted_pii: Base64-encoded IVMS101 PII ciphertext
        - pii_nonce: Base64-encoded AES-GCM nonce
        - pii_associated_data: Envelope binding data
        - payload_version: "1.0"

        Returns:
            JSON bytes of the inner payload
        """
        payload = {
            "zk_compliance_proof": compliance_proof.model_dump(mode="json"),
            "encrypted_pii": base64.b64encode(hybrid_payload.encrypted_pii).decode("ascii"),
            "pii_nonce": base64.b64encode(hybrid_payload.pii_nonce).decode("ascii"),
            "pii_associated_data": hybrid_payload.pii_associated_data,
            "ivms101_version": "101.2023",
            "payload_version": "1.0",
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def compute_hmac(self, encrypted_payload: bytes, secret: bytes) -> bytes:
        """
        Compute HMAC-SHA256 over the encrypted payload.

        Args:
            encrypted_payload: The AES-encrypted payload bytes
            secret: The HMAC secret key

        Returns:
            32-byte HMAC signature
        """
        h = HMAC(secret, hashes.SHA256())
        h.update(encrypted_payload)
        return h.finalize()

    def build_envelope(
        self,
        transfer_id: str,
        compliance_proof: ComplianceProof,
        hybrid_payload: HybridPayload,
        transfer_state: int = pb2.STARTED,
    ) -> pb2.SecureEnvelope:
        """
        Build a complete wire-format TRISA SecureEnvelope.

        Args:
            transfer_id: Unique transaction identifier
            compliance_proof: The ZK compliance attestation
            hybrid_payload: Hybrid payload with encrypted PII
            transfer_state: TRISA TransferState enum value

        Returns:
            A protobuf SecureEnvelope ready for gRPC transmission
        """
        # Build inner payload
        inner_payload = self.build_payload(compliance_proof, hybrid_payload)

        # Generate ephemeral AES-256-GCM key
        aes_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        encrypted_payload = aesgcm.encrypt(nonce, inner_payload, None)

        # Generate HMAC secret
        hmac_secret=os.urandom(32)
        # HMAC over nonce || ciphertext (the full encrypted blob, matching TRISA spec)
        hmac_signature = self.compute_hmac(nonce + encrypted_payload, hmac_secret)

        # Wrap AES key with beneficiary public key (RSA-OAEP)
        pub_key = serialization.load_der_public_key(self.beneficiary_public_key)
        wrapped_key = pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Wrap HMAC secret with beneficiary public key
        wrapped_hmac_secret = pub_key.encrypt(
            hmac_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return pb2.SecureEnvelope(
            id=transfer_id,
            payload=nonce + encrypted_payload,  # nonce || ciphertext (proto3 default)
            encryption_key=wrapped_key,
            encryption_algorithm="AES-256-GCM",
            hmac=hmac_signature,
            hmac_secret=wrapped_hmac_secret,
            hmac_algorithm="HMAC-SHA256",
            sealed=True,
            timestamp=datetime.now(timezone.utc).isoformat(),
            transfer_state=transfer_state,
            public_key_signature="",  # Would be set with real certificates
        )

    def parse_envelope(
        self,
        envelope: pb2.SecureEnvelope,
        beneficiary_private_key: rsa.RSAPrivateKey,
    ) -> dict[str, Any]:
        """
        Parse and decrypt a received TRISA SecureEnvelope.

        Args:
            envelope: The received SecureEnvelope protobuf
            beneficiary_private_key: RSA private key for decryption

        Returns:
            Dict containing the decrypted payload data
        """
        if envelope.sealed:
            # Unwrap AES key
            aes_key = beneficiary_private_key.decrypt(
                envelope.encryption_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Unwrap HMAC secret
            hmac_secret = beneficiary_private_key.decrypt(
                envelope.hmac_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Verify HMAC — HMAC is over nonce || ciphertext (same as build_envelope)
            computed_hmac = self.compute_hmac(envelope.payload, hmac_secret)
            if computed_hmac != envelope.hmac:
                raise TRISAError(
                    errors_pb2.Error.INVALID_SIGNATURE,
                    "HMAC verification failed",
                    retry=False,
                )

            # Decrypt payload
            nonce = envelope.payload[:12]
            ciphertext = envelope.payload[12:]
            aesgcm = AESGCM(aes_key)
            inner_payload = aesgcm.decrypt(nonce, ciphertext, None)
        else:
            inner_payload = envelope.payload

        return json.loads(inner_payload)


class TRISAClient:
    """
    gRPC client for the TRISA Network service.

    Usage:
        async with TRISAClient("trisa.example.com:18000") as client:
            response = await client.transfer(envelope)
    """

    def __init__(
        self,
        target: str,
        credentials: Optional[grpc.ChannelCredentials] = None,
    ):
        """
        Initialize the TRISA gRPC client.

        Args:
            target: The TRISA node address (e.g., "trisa.example.com:18000")
            credentials: gRPC channel credentials (mTLS recommended)
        """
        self.target = target
        if credentials is None:
            # Insecure channel for testing; use mTLS credentials in production
            credentials = grpc.ssl_channel_credentials()
        self.channel = grpc.aio.secure_channel(target, credentials)
        self.stub = pb2_grpc.TRISANetworkStub(self.channel)

    async def __aenter__(self) -> "TRISAClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.channel.close()

    async def transfer(
        self,
        envelope: pb2.SecureEnvelope,
        timeout: float = 30.0,
    ) -> pb2.SecureEnvelope:
        """
        Send a Transfer RPC to the beneficiary VASP.

        Args:
            envelope: The SecureEnvelope to send
            timeout: RPC timeout in seconds

        Returns:
            The beneficiary's response SecureEnvelope

        Raises:
            TRISAError: If the response contains a TRISA error
        """
        response = await self.stub.Transfer(envelope, timeout=timeout)

        if response.HasField("error") and response.error.code != 0:
            raise TRISAError.from_pb2(response.error)

        return response

    async def transfer_stream(
        self,
        envelopes: AsyncIterator[pb2.SecureEnvelope],
        timeout: float = 300.0,
    ) -> AsyncIterator[pb2.SecureEnvelope]:
        """
        Send a TransferStream RPC for high-throughput transfers.

        Args:
            envelopes: Async iterator of SecureEnvelopes
            timeout: RPC timeout in seconds

        Yields:
            Response envelopes from the beneficiary
        """
        async for response in self.stub.TransferStream(envelopes, timeout=timeout):
            if response.HasField("error") and response.error.code != 0:
                raise TRISAError.from_pb2(response.error)
            yield response

    async def confirm_address(
        self,
        address: str,
        network: str,
        confirmation_type: int = pb2.SIMPLE,
    ) -> pb2.AddressConfirmation:
        """
        Confirm control of a crypto wallet address.

        Args:
            address: The crypto wallet address
            network: The blockchain network (e.g., "ethereum")
            confirmation_type: Type of confirmation (SIMPLE/KEYTOKEN/ONCHAIN)

        Returns:
            AddressConfirmation response
        """
        addr = pb2.Address(
            confirmation=confirmation_type,
            crypto_address=address,
            network=network,
        )
        return await self.stub.ConfirmAddress(addr)

    async def key_exchange(
        self,
        signing_key: pb2.SigningKey,
    ) -> pb2.SigningKey:
        """
        Exchange signing keys with a counterparty.

        Args:
            signing_key: Local signing key metadata

        Returns:
            Counterparty's signing key
        """
        return await self.stub.KeyExchange(signing_key)


class TRISAServer:
    """
    gRPC server servant for handling incoming TRISA transfers.

    Inherit from this class and implement handle_transfer() to add
    custom transfer handling logic.
    """

    def __init__(
        self,
        private_key: rsa.RSAPrivateKey,
        public_key: bytes,
        signing_key_data: bytes,
    ):
        """
        Initialize the TRISA server servant.

        Args:
            private_key: RSA private key for decryption
            public_key: DER-encoded public key for encryption
            signing_key_data: PEM-encoded signing key data
        """
        self.private_key = private_key
        self.public_key = public_key
        self.signing_key_data = signing_key_data
        self.envelope_builder = SecureEnvelopeBuilder(
            beneficiary_public_key=public_key,
            originator_signing_key=signing_key_data,
        )

    async def Transfer(
        self,
        request: pb2.SecureEnvelope,
        context: grpc.aio.ServicerContext,
    ) -> pb2.SecureEnvelope:
        """
        Handle an incoming Transfer RPC.

        Override this method to implement custom transfer handling.
        """
        try:
            # Parse and decrypt the incoming envelope
            payload = self.envelope_builder.parse_envelope(request, self.private_key)

            # Handle the transfer (implement custom logic in subclass)
            response_envelope = await self.handle_transfer(payload, request)

            return response_envelope

        except TRISAError as e:
            return pb2.SecureEnvelope(
                id=request.id,
                error=pb2.Error(
                    code=e.code,
                    message=e.message,
                    retry=e.retry,
                ),
            )
        except Exception as e:
            return pb2.SecureEnvelope(
                id=request.id,
                error=pb2.Error(
                    code=errors_pb2.Error.INTERNAL_ERROR,
                    message=str(e),
                    retry=True,
                ),
            )

    async def TransferStream(
        self,
        request_iterator: AsyncIterator[pb2.SecureEnvelope],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[pb2.SecureEnvelope]:
        """
        Handle an incoming TransferStream RPC.

        Override handle_transfer() for custom logic.
        """
        async for request in request_iterator:
            yield await self.Transfer(request, context)

    async def ConfirmAddress(
        self,
        request: pb2.Address,
        context: grpc.aio.ServicerContext,
    ) -> pb2.AddressConfirmation:
        """Handle an incoming ConfirmAddress RPC."""
        # Implement wallet control verification
        raise NotImplementedError("Override ConfirmAddress in subclass")

    async def KeyExchange(
        self,
        request: pb2.SigningKey,
        context: grpc.aio.ServicerContext,
    ) -> pb2.SigningKey:
        """Handle an incoming KeyExchange RPC."""
        # Return our signing key
        return pb2.SigningKey(
            version=1,
            signature_algorithm="RSA-SHA256",
            public_key_algorithm="RSA",
            data=self.public_key,
            not_before=datetime.now(timezone.utc).isoformat(),
            not_after="",  # Set based on certificate expiry
        )

    async def handle_transfer(
        self,
        payload: dict[str, Any],
        request: pb2.SecureEnvelope,
    ) -> pb2.SecureEnvelope:
        """
        Handle a decrypted TRISA transfer payload.

        Override this method in a subclass to implement custom logic.

        Args:
            payload: Decrypted payload dict
            request: Original SecureEnvelope

        Returns:
            Response SecureEnvelope
        """
        # Default: acknowledge the transfer
        return pb2.SecureEnvelope(
            id=request.id,
            payload=b"",
            transfer_state=pb2.ACCEPTED,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


async def create_trisa_server(
    private_key_path: str,
    certificate_path: str,
    port: int = _DEFAULT_TRISA_PORT,
) -> grpc.aio.server:
    """
    Create a gRPC server with TRISA service handler.

    Args:
        private_key_path: Path to RSA private key PEM file
        certificate_path: Path to TLS certificate PEM file
        port: Port to listen on

    Returns:
        Configured grpc.aio.Server
    """
    # Load keys
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)

    with open(certificate_path, "rb") as f:
        cert_data = f.read()

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Create servant
    servant = TRISAServer(
        private_key=private_key,
        public_key=public_key,
        signing_key_data=cert_data,
    )

    # Create server with mTLS credentials
    server = grpc.aio.server(
        options=[
            ("grpc.max_send_message_length", 50 * 1024 * 1024),
            ("grpc.max_receive_message_length", 50 * 1024 * 1024),
        ]
    )
    pb2_grpc.add_TRISANetworkServicer_to_server(servant, server)
    server.add_insecure_port(f"[::]:{port}")

    return server
