"""
TRISA gRPC bridge — wraps a hybrid payload in a TRISA SecureEnvelope.

TRISA requires:
  - mTLS certificates from the TRISA Global Directory Service (GDS).
  - Encrypted IVMS101 payload (AES-256-GCM + RSA key wrapping).
  - Non-repudiation via HMAC (computed separately by the TRISA SDK).

Wire format (SecureEnvelope dict):
  ``encrypted_payload``
      Hex-encoded bytes: 12-byte AES-GCM nonce || ciphertext || 16-byte tag.
      The plaintext is a JSON object containing:
        - ``zk_compliance_proof``: full ComplianceProof model dump
        - ``encrypted_pii``:       base64 ciphertext of IVMS101 PII
        - ``encryption_algorithm``: algorithm used for PII encryption
        - ``pii_nonce``:           base64 nonce for PII decryption
        - ``pii_associated_data``: AAD binding the PII to this envelope
        - ``ivms101_version``:     IVMS101 schema version
        - ``payload_version``:     hybrid payload schema version
  ``encryption_algorithm``
      Always ``"AES256_GCM"``.
  ``wrapped_key``
      Hex-encoded RSA-OAEP-wrapped AES-256 key (SHA-256 MGF1 + SHA-256 hash).
  ``hmac_signature``
      Empty string — computed separately by the TRISA SDK.
  ``override_header.envelope_type``
      ``"ZK_TRAVEL_RULE_V1"`` so the beneficiary knows to expect a ZK proof
      inside the decrypted payload.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload

__all__ = ["TRISABridge"]


class TRISABridge:
    """Wraps hybrid Travel Rule payloads in TRISA SecureEnvelope format."""

    def build_secure_envelope(
        self,
        compliance_proof: ComplianceProof,
        hybrid_payload: HybridPayload,
        beneficiary_public_key: bytes,
    ) -> dict[str, Any]:
        """
        Build a TRISA SecureEnvelope containing the hybrid ZK payload.

        The encrypted payload bundles both the ZK ComplianceProof and the
        encrypted PII.  The beneficiary decrypts via mTLS, extracts both
        components, and can independently verify the Groth16 proof.

        Parameters
        ----------
        compliance_proof:
            The ZK compliance attestation for this transfer.
        hybrid_payload:
            The combined ZK proof + encrypted PII bundle.
        beneficiary_public_key:
            DER-encoded RSA public key of the beneficiary VASP, obtained
            from the TRISA Global Directory Service.

        Returns
        -------
        dict
            A SecureEnvelope-shaped dict ready for TRISA gRPC transmission.
            The ``hmac_signature`` field is left empty; it must be computed
            by the TRISA SDK before sending.
        """
        # --- serialise the hybrid payload to JSON bytes ---
        payload_json: bytes = json.dumps(
            {
                "zk_compliance_proof": compliance_proof.model_dump(),
                "encrypted_pii": base64.b64encode(
                    hybrid_payload.encrypted_pii
                ).decode("ascii"),
                "encryption_algorithm": hybrid_payload.encryption_algorithm,
                "pii_nonce": base64.b64encode(
                    hybrid_payload.pii_nonce
                ).decode("ascii"),
                "pii_associated_data": hybrid_payload.pii_associated_data,
                "ivms101_version": "101.2023",
                "payload_version": "1.0",
            },
            separators=(",", ":"),
        ).encode("utf-8")

        # --- encrypt with ephemeral AES-256-GCM ---
        aes_key: bytes = os.urandom(32)
        nonce: bytes = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext: bytes = aesgcm.encrypt(nonce, payload_json, None)

        # --- wrap AES key with beneficiary RSA public key (OAEP + SHA-256) ---
        pub_key = serialization.load_der_public_key(beneficiary_public_key)
        wrapped_key: bytes = pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return {
            "encrypted_payload": (nonce + ciphertext).hex(),
            "encryption_algorithm": "AES256_GCM",
            "wrapped_key": wrapped_key.hex(),
            "hmac_signature": "",  # computed separately via TRISA SDK
            "override_header": {
                "not_after": compliance_proof.proof_expires_at,
                "envelope_type": "ZK_TRAVEL_RULE_V1",
            },
        }
