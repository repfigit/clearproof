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
        - ``pii_nonce``:           base64 nonce for PII decryption (empty for HPKE v2)
        - ``pii_associated_data``: AAD binding the PII to this envelope
        - ``pii_envelope``:        HPKE v2 envelope (``enc``/``kid``/...), or null for v1
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

The PII fields come from :meth:`HybridPayload.pii_wire_fields`. ``pii_envelope``
is an additive key inside the encrypted JSON (``payload_version`` stays
``"1.0"``); receivers that predate it ignore it, and
:meth:`TRISABridge.open_secure_envelope` treats its absence as legacy v1.
"""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
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
                **hybrid_payload.pii_wire_fields(),
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

    @staticmethod
    def open_secure_envelope(
        envelope: dict[str, Any],
        beneficiary_private_key: rsa.RSAPrivateKey,
    ) -> HybridPayload:
        """
        Beneficiary side of :meth:`build_secure_envelope`.

        Unwraps the AES key, decrypts the bundle and rebuilds the
        :class:`HybridPayload` (including any HPKE v2 envelope) so the
        beneficiary can decrypt the PII with its own key. PII stays encrypted.
        """
        aes_key = beneficiary_private_key.decrypt(
            bytes.fromhex(envelope["wrapped_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        blob = bytes.fromhex(envelope["encrypted_payload"])
        inner = json.loads(AESGCM(aes_key).decrypt(blob[:12], blob[12:], None))
        proof = ComplianceProof.model_validate(inner["zk_compliance_proof"])
        return HybridPayload.from_pii_wire_fields(proof, inner)
