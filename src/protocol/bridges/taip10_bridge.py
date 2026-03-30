"""
TAIP-10 selective disclosure bridge — maps a hybrid payload to a W3C
Verifiable Presentation containing ZK compliance proof credentials.

Wire format (JSON-LD, W3C VC Data Model v1):
  The outer object is a **VerifiablePresentation** with type
  ``["VerifiablePresentation", "TravelRuleCompliance"]``.

  ``verifiableCredential[0]``
      A **VerifiableCredential** of type ``["VerifiableCredential",
      "ZKComplianceProof"]`` whose ``credentialSubject`` contains the
      ComplianceProof public signals (proof_id, groth16_proof,
      public_signals, verification_key, jurisdiction, amount_tier).
      No PII appears in the credential — only the ZK attestation.

  ``encryptedPII``
      An opaque object referencing the encrypted PII ciphertext, its
      encryption method, nonce, and associated data.  This satisfies the
      regulatory requirement to *transmit* PII while keeping it out of
      the VC itself.

  ``proof``
      A placeholder for the presentation proof.  In production this would
      be a JSON-LD / Ed25519Signature2020 or similar linked-data proof
      over the VP; here we include the structure so downstream consumers
      know where to attach or verify it.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

from src.protocol.compliance_proof import ComplianceProof
from src.protocol.hybrid_payload import HybridPayload

__all__ = ["TAIP10Bridge"]


class TAIP10Bridge:
    """Builds TAIP-10 Verifiable Presentations from hybrid ZK payloads."""

    def build_verifiable_presentation(
        self,
        compliance_proof: ComplianceProof,
        originator_vasp_did: str,
    ) -> dict[str, Any]:
        """
        Build a TAIP-10 Verifiable Presentation containing the ZK
        compliance proof as a Verifiable Credential.

        The VP follows the W3C Verifiable Credentials Data Model v1
        (https://www.w3.org/TR/vc-data-model/) and embeds the
        ComplianceProof public signals as credential claims.  No PII is
        included in the credential itself.

        Parameters
        ----------
        compliance_proof:
            The ZK compliance attestation for this transfer.
        originator_vasp_did:
            Decentralised identifier of the originating VASP, used as the
            VC issuer and VP holder.

        Returns
        -------
        dict
            A W3C-conformant Verifiable Presentation (JSON-LD).
        """
        issuance_date: str = datetime.fromtimestamp(
            compliance_proof.proof_generated_at, tz=timezone.utc
        ).isoformat()

        expiration_date: str = datetime.fromtimestamp(
            compliance_proof.proof_expires_at, tz=timezone.utc
        ).isoformat()

        verifiable_credential: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://tap.rsvp/taip-10/v1",
            ],
            "type": ["VerifiableCredential", "ZKComplianceProof"],
            "issuer": originator_vasp_did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "proof_id": compliance_proof.proof_id,
                "transfer_id": compliance_proof.transfer_id,
                "groth16_proof": compliance_proof.groth16_proof,
                "public_signals": compliance_proof.public_signals,
                "verification_key": compliance_proof.verification_key,
                "jurisdiction": compliance_proof.jurisdiction,
                "amount_tier": compliance_proof.amount_tier,
                "sar_review_flag": compliance_proof.sar_review_flag,
            },
        }

        return {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://tap.rsvp/taip-10/v1",
            ],
            "type": ["VerifiablePresentation", "TravelRuleCompliance"],
            "holder": originator_vasp_did,
            "verifiableCredential": [verifiable_credential],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": issuance_date,
                "verificationMethod": f"{originator_vasp_did}#key-1",
                "proofPurpose": "authentication",
                "proofValue": "",  # populated by signing layer
            },
        }
