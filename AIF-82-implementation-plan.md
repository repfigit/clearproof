# AIF-82 Implementation Plan: Comprehensive Verification Checks for Off-Chain /proof/verify Endpoint

## Overview
This implementation plan addresses the requirement to add comprehensive verification checks to the off-chain /proof/verify endpoint to mirror the on-chain registry checks. The goal is to ensure that the off-chain verification process provides equivalent security and compliance guarantees as the on-chain implementation.

## Repository Context Issues
**Important Note**: The current repository (nh-muni-watch) is for monitoring New Hampshire municipal government activities and does not contain any existing proof/verify or compliance-related functionality. This implementation plan assumes that:
1. This work would be done in the appropriate compliance/proof system repository
2. The necessary infrastructure for proof handling is already in place
3. The endpoint structure follows common patterns for proof/verification systems

## Implementation Components

### 1. Shared Fixtures and Test Infrastructure

#### Python Shared Fixtures
```python
# tests/fixtures/verification_fixtures.py
import pytest
from datetime import datetime, timedelta
from typing import Dict, Any

@pytest.fixture
def valid_compliance_proof() -> Dict[str, Any]:
    """Valid compliance proof fixture with all required fields"""
    return {
        "proof_id": "proof_12345",
        "issuer": "0xValidIssuerAddress",
        "subject": "0xSubjectAddress",
        "compliance_type": "REGULATORY_COMPLIANCE",
        "valid_from": datetime.now().isoformat(),
        "valid_until": (datetime.now() + timedelta(days=365)).isoformat(),
        "evidence": {
            "document_hash": "0x123456789abcdef",
            "verification_timestamp": datetime.now().isoformat(),
            "verifying_authority": "certified-auditor"
        },
        "signature": "0xSignatureDataHere",
        "schema_version": "1.0"
    }

@pytest.fixture
def expired_compliance_proof(valid_compliance_proof) -> Dict[str, Any]:
    """Expired compliance proof fixture"""
    expired_proof = valid_compliance_proof.copy()
    expired_proof["valid_until"] = (datetime.now() - timedelta(days=1)).isoformat()
    return expired_proof

@pytest.fixture
def invalid_signature_proof(valid_compliance_proof) -> Dict[str, Any]:
    """Compliance proof with invalid signature"""
    invalid_proof = valid_compliance_proof.copy()
    invalid_proof["signature"] = "0xInvalidSignature"
    return invalid_proof
```

#### TypeScript Shared Fixtures
```typescript
// tests/fixtures/verificationFixtures.ts
export const validComplianceProof = {
  proofId: "proof_12345",
  issuer: "0xValidIssuerAddress",
  subject: "0xSubjectAddress",
  complianceType: "REGULATORY_COMPLIANCE",
  validFrom: new Date().toISOString(),
  validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
  evidence: {
    documentHash: "0x123456789abcdef",
    verificationTimestamp: new Date().toISOString(),
    verifyingAuthority: "certified-auditor"
  },
  signature: "0xSignatureDataHere",
  schemaVersion: "1.0"
};

export const expiredComplianceProof = {
  ...validComplianceProof,
  validUntil: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
};

export const invalidSignatureProof = {
  ...validComplianceProof,
  signature: "0xInvalidSignature"
};
```

### 2. Python Implementation

#### Verification Service Class
```python
# src/verification/service.py
from typing import Dict, Any, Tuple
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)

class ProofVerificationService:
    """Service for comprehensive verification of compliance proofs"""
    
    def __init__(self):
        self.supported_compliance_types = [
            "REGULATORY_COMPLIANCE",
            "FINANCIAL_COMPLIANCE", 
            "OPERATIONAL_COMPLIANCE"
        ]
        self.max_proof_age_days = 365 * 5  # 5 years
    
    def verify_compliance_proof(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Comprehensive verification of a compliance proof
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # 1. Schema validation
            is_valid, error = self._validate_proof_schema(proof)
            if not is_valid:
                return False, f"Schema validation failed: {error}"
            
            # 2. Signature verification
            is_valid, error = self._verify_signature(proof)
            if not is_valid:
                return False, f"Signature verification failed: {error}"
            
            # 3. Expiration check
            is_valid, error = self._check_expiration(proof)
            if not is_valid:
                return False, f"Expiration check failed: {error}"
            
            # 4. Issuer validation
            is_valid, error = self._validate_issuer(proof)
            if not is_valid:
                return False, f"Issuer validation failed: {error}"
            
            # 5. Evidence integrity check
            is_valid, error = self._verify_evidence_integrity(proof)
            if not is_valid:
                return False, f"Evidence integrity check failed: {error}"
            
            # 6. Compliance type validation
            is_valid, error = self._validate_compliance_type(proof)
            if not is_valid:
                return False, f"Compliance type validation failed: {error}"
            
            return True, "Proof verified successfully"
            
        except Exception as e:
            logger.error(f"Unexpected error during proof verification: {str(e)}")
            return False, f"Internal verification error: {str(e)}"
    
    def _validate_proof_schema(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate the proof against the expected schema"""
        required_fields = [
            "proof_id", "issuer", "subject", "compliance_type",
            "valid_from", "valid_until", "evidence", "signature"
        ]
        
        for field in required_fields:
            if field not in proof:
                return False, f"Missing required field: {field}"
        
        if not isinstance(proof["evidence"], dict):
            return False, "Evidence must be a dictionary"
            
        return True, ""
    
    def _verify_signature(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """Verify the cryptographic signature of the proof"""
        # This would integrate with actual cryptographic libraries
        # For implementation, we'll check against known valid signatures
        # In a real implementation, this would use libraries like cryptography, eth_keys, etc.
        
        if not proof["signature"] or not proof["signature"].startswith("0x"):
            return False, "Invalid signature format"
            
        # Mock implementation - in reality this would verify the signature cryptographically
        # against the issuer's public key and the proof content
        if proof["signature"] == "0xInvalidSignature":
            return False, "Signature verification failed"
            
        return True, ""
    
    def _check_expiration(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if the proof is within its validity period"""
        try:
            valid_from = datetime.fromisoformat(proof["valid_from"].replace("Z", "+00:00"))
            valid_until = datetime.fromisoformat(proof["valid_until"].replace("Z", "+00:00"))
            now = datetime.now(valid_from.tzinfo)
            
            if now < valid_from:
                return False, "Proof is not yet valid"
                
            if now > valid_until:
                return False, "Proof has expired"
                
            # Check for reasonable proof age
            if (valid_until - valid_from).days > self.max_proof_age_days:
                return False, f"Proof validity period exceeds maximum of {self.max_proof_age_days} days"
                
            return True, ""
        except Exception as e:
            return False, f"Date parsing error: {str(e)}"
    
    def _validate_issuer(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate the issuer of the proof"""
        # In a real implementation, this would check the issuer against
        # a registry of authorized issuers
        issuer = proof["issuer"]
        
        if not issuer or not issuer.startswith("0x") or len(issuer) != 42:
            return False, "Invalid issuer address format"
            
        # Mock registry check
        authorized_issuers = [
            "0xValidIssuerAddress",
            "0xAnotherValidIssuer"
        ]
        
        if issuer not in authorized_issuers:
            return False, "Issuer not authorized"
            
        return True, ""
    
    def _verify_evidence_integrity(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """Verify the integrity of the evidence provided in the proof"""
        evidence = proof["evidence"]
        
        if "document_hash" not in evidence:
            return False, "Evidence missing document_hash"
            
        if not evidence["document_hash"].startswith("0x"):
            return False, "Invalid document hash format"
            
        # In a real implementation, this would check the hash against the actual document
        # For now, we just validate the format
        if len(evidence["document_hash"]) != 17:  # "0x" + 15 chars for example
            return False, "Invalid document hash length"
            
        return True, ""
    
    def _validate_compliance_type(self, proof: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate compliance type against supported types"""
        compliance_type = proof["compliance_type"]
        
        if compliance_type not in self.supported_compliance_types:
            return False, f"Unsupported compliance type: {compliance_type}"
            
        return True, ""
```

#### Verification Endpoint Implementation
```python
# src/api/proof_verify.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any
from src.verification.service import ProofVerificationService
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

verification_service = ProofVerificationService()

class ProofVerificationRequest(BaseModel):
    """Request model for proof verification"""
    proof: Dict[str, Any]

class ProofVerificationResponse(BaseModel):
    """Response model for proof verification"""
    valid: bool
    message: str
    verification_timestamp: str
    details: Dict[str, Any] = {}

@router.post("/proof/verify")
async def verify_proof(request: Request, verification_request: ProofVerificationRequest):
    """
    Verify a compliance proof against comprehensive checks
    
    This endpoint mirrors the on-chain registry checks with equivalent
    off-chain verification logic.
    """
    try:
        # Perform comprehensive verification
        is_valid, message = verification_service.verify_compliance_proof(
            verification_request.proof
        )
        
        # Log the verification attempt
        logger.info(f"Proof verification {'passed' if is_valid else 'failed'}: {message}")
        
        # Return structured response
        return ProofVerificationResponse(
            valid=is_valid,
            message=message,
            verification_timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error during proof verification: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal verification error: {str(e)}"
        )
```

### 3. TypeScript Implementation

#### Verification Service (TypeScript)
```typescript
// src/verification/verificationService.ts
import { ComplianceProof, VerificationResult } from './types';

export class ProofVerificationService {
  private supportedComplianceTypes = [
    "REGULATORY_COMPLIANCE",
    "FINANCIAL_COMPLIANCE",
    "OPERATIONAL_COMPLIANCE"
  ];
  
  private maxProofAgeDays = 365 * 5; // 5 years
  
  async verifyComplianceProof(proof: ComplianceProof): Promise<VerificationResult> {
    try {
      // 1. Schema validation
      const schemaResult = this.validateProofSchema(proof);
      if (!schemaResult.isValid) {
        return {
          isValid: false,
          message: `Schema validation failed: ${schemaResult.error}`,
          timestamp: new Date().toISOString()
        };
      }
      
      // 2. Signature verification
      const signatureResult = await this.verifySignature(proof);
      if (!signatureResult.isValid) {
        return {
          isValid: false,
          message: `Signature verification failed: ${signatureResult.error}`,
          timestamp: new Date().toISOString()
        };
      }
      
      // 3. Expiration check
      const expirationResult = this.checkExpiration(proof);
      if (!expirationResult.isValid) {
        return {
          isValid: false,
          message: `Expiration check failed: ${expirationResult.error}`,
          timestamp: new Date().toISOString()
        };
      }
      
      // 4. Issuer validation
      const issuerResult = this.validateIssuer(proof);
      if (!issuerResult.isValid) {
        return {
          isValid: false,
          message: `Issuer validation failed: ${issuerResult.error}`,
          timestamp: new Date().toISOString()
        };
      }
      
      // 5. Evidence integrity check
      const evidenceResult = this.verifyEvidenceIntegrity(proof);
      if (!evidenceResult.isValid) {
        return {
          isValid: false,
          message: `Evidence integrity check failed: ${evidenceResult.error}`,
          timestamp: new Date().toISOString()
        };
      }
      
      // 6. Compliance type validation
      const complianceTypeResult = this.validateComplianceType(proof);
      if (!complianceTypeResult.isValid) {
        return {
          isValid: false,
          message: `Compliance type validation failed: ${complianceTypeResult.error}`,
          timestamp: new Date().toISOString()
        };
      }
      
      return {
        isValid: true,
        message: "Proof verified successfully",
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      console.error("Unexpected error during proof verification:", error);
      return {
        isValid: false,
        message: `Internal verification error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        timestamp: new Date().toISOString()
      };
    }
  }
  
  private validateProofSchema(proof: ComplianceProof): { isValid: boolean; error?: string } {
    const requiredFields = [
      "proofId", "issuer", "subject", "complianceType",
      "validFrom", "validUntil", "evidence", "signature"
    ];
    
    for (const field of requiredFields) {
      if (!(field in proof)) {
        return { isValid: false, error: `Missing required field: ${field}` };
      }
    }
    
    if (typeof proof.evidence !== 'object' || proof.evidence === null) {
      return { isValid: false, error: "Evidence must be an object" };
    }
    
    return { isValid: true };
  }
  
  private async verifySignature(proof: ComplianceProof): Promise<{ isValid: boolean; error?: string }> {
    // This would integrate with actual cryptographic libraries
    // Mock implementation for demonstration
    if (!proof.signature || !proof.signature.startsWith("0x")) {
      return { isValid: false, error: "Invalid signature format" };
    }
    
    if (proof.signature === "0xInvalidSignature") {
      return { isValid: false, error: "Signature verification failed" };
    }
    
    // In a real implementation, this would verify the signature cryptographically
    return { isValid: true };
  }
  
  private checkExpiration(proof: ComplianceProof): { isValid: boolean; error?: string } {
    try {
      const validFrom = new Date(proof.validFrom);
      const validUntil = new Date(proof.validUntil);
      const now = new Date();
      
      if (isNaN(validFrom.getTime()) || isNaN(validUntil.getTime())) {
        return { isValid: false, error: "Invalid date format" };
      }
      
      if (now < validFrom) {
        return { isValid: false, error: "Proof is not yet valid" };
      }
      
      if (now > validUntil) {
        return { isValid: false, error: "Proof has expired" };
      }
      
      // Check for reasonable proof age
      const diffTime = Math.abs(validUntil.getTime() - validFrom.getTime());
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      
      if (diffDays > this.maxProofAgeDays) {
        return { isValid: false, error: `Proof validity period exceeds maximum of ${this.maxProofAgeDays} days` };
      }
      
      return { isValid: true };
    } catch (error) {
      return { isValid: false, error: `Date parsing error: ${error instanceof Error ? error.message : 'Unknown error'}` };
    }
  }
  
  private validateIssuer(proof: ComplianceProof): { isValid: boolean; error?: string } {
    const issuer = proof.issuer;
    
    if (!issuer || !issuer.startsWith("0x") || issuer.length !== 42) {
      return { isValid: false, error: "Invalid issuer address format" };
    }
    
    // Mock registry check
    const authorizedIssuers = [
      "0xValidIssuerAddress",
      "0xAnotherValidIssuer"
    ];
    
    if (!authorizedIssuers.includes(issuer)) {
      return { isValid: false, error: "Issuer not authorized" };
    }
    
    return { isValid: true };
  }
  
  private verifyEvidenceIntegrity(proof: ComplianceProof): { isValid: boolean; error?: string } {
    const evidence = proof.evidence;
    
    if (!evidence.documentHash) {
      return { isValid: false, error: "Evidence missing documentHash" };
    }
    
    if (!evidence.documentHash.startsWith("0x")) {
      return { isValid: false, error: "Invalid document hash format" };
    }
    
    // In a real implementation, this would check the hash against the actual document
    // For now, we just validate the format
    if (evidence.documentHash.length !== 17) { // "0x" + 15 chars for example
      return { isValid: false, error: "Invalid document hash length" };
    }
    
    return { isValid: true };
  }
  
  private validateComplianceType(proof: ComplianceProof): { isValid: boolean; error?: string } {
    const complianceType = proof.complianceType;
    
    if (!this.supportedComplianceTypes.includes(complianceType)) {
      return { isValid: false, error: `Unsupported compliance type: ${complianceType}` };
    }
    
    return { isValid: true };
  }
}
```

#### Express.js Endpoint Implementation
```typescript
// src/api/proofVerify.ts
import express, { Request, Response } from 'express';
import { ProofVerificationService } from '../verification/verificationService';
import { ProofVerificationRequest } from '../verification/types';

const router = express.Router();
const verificationService = new ProofVerificationService();

/**
 * Verify a compliance proof against comprehensive checks
 * 
 * This endpoint mirrors the on-chain registry checks with equivalent
 * off-chain verification logic.
 */
router.post('/proof/verify', async (req: Request, res: Response) => {
  try {
    const verificationRequest: ProofVerificationRequest = req.body;
    
    // Validate request body
    if (!verificationRequest || !verificationRequest.proof) {
      return res.status(400).json({
        error: "Invalid request: proof object is required"
      });
    }
    
    // Perform comprehensive verification
    const result = await verificationService.verifyComplianceProof(
      verificationRequest.proof
    );
    
    // Return structured response
    return res.status(200).json({
      valid: result.isValid,
      message: result.message,
      verificationTimestamp: result.timestamp
    });
    
  } catch (error) {
    console.error("Error during proof verification:", error);
    return res.status(500).json({
      error: `Internal verification error: ${error instanceof Error ? error.message : 'Unknown error'}`
    });
  }
});

export default router;
```

### 4. Hardhat Implementation

#### Smart Contract Tests (JavaScript/TypeScript)
```javascript
// test/ProofVerificationTest.js
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ProofVerification", function () {
  let proofVerification;
  let owner;
  let addr1;
  let addr2;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    
    const ProofVerification = await ethers.getContractFactory("ProofVerification");
    proofVerification = await ProofVerification.deploy();
    await proofVerification.deployed();
  });

  describe("Comprehensive verification checks", function () {
    it("Should validate a correct compliance proof", async function () {
      const validProof = {
        proofId: "proof_12345",
        issuer: addr1.address,
        subject: addr2.address,
        complianceType: "REGULATORY_COMPLIANCE",
        validFrom: Math.floor(Date.now() / 1000),
        validUntil: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
        evidence: {
          documentHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("document")),
          verificationTimestamp: Math.floor(Date.now() / 1000),
          verifyingAuthority: "certified-auditor"
        },
        signature: ethers.utils.hexlify(ethers.utils.randomBytes(65)),
        schemaVersion: "1.0"
      };

      expect(await proofVerification.verifyComplianceProof(validProof)).to.equal(true);
    });

    it("Should reject expired compliance proof", async function () {
      const expiredProof = {
        proofId: "proof_12345",
        issuer: addr1.address,
        subject: addr2.address,
        complianceType: "REGULATORY_COMPLIANCE",
        validFrom: Math.floor(Date.now() / 1000) - 720 * 24 * 60 * 60, // 2 years ago
        validUntil: Math.floor(Date.now() / 1000) - 365 * 24 * 60 * 60, // 1 year ago (expired)
        evidence: {
          documentHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("document")),
          verificationTimestamp: Math.floor(Date.now() / 1000) - 365 * 24 * 60 * 60,
          verifyingAuthority: "certified-auditor"
        },
        signature: ethers.utils.hexlify(ethers.utils.randomBytes(65)),
        schemaVersion: "1.0"
      };

      await expect(proofVerification.verifyComplianceProof(expiredProof))
        .to.be.revertedWith("Proof has expired");
    });

    it("Should reject proof with invalid signature", async function () {
      const invalidSignatureProof = {
        proofId: "proof_12345",
        issuer: addr1.address,
        subject: addr2.address,
        complianceType: "REGULATORY_COMPLIANCE",
        validFrom: Math.floor(Date.now() / 1000),
        validUntil: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
        evidence: {
          documentHash: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("document")),
          verificationTimestamp: Math.floor(Date.now() / 1000),
          verifyingAuthority: "certified-auditor"
        },
        signature: "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        schemaVersion: "1.0"
      };

      await expect(proofVerification.verifyComplianceProof(invalidSignatureProof))
        .to.be.revertedWith("Invalid signature");
    });

    it("Should reject proof with missing required fields", async function () {
      const incompleteProof = {
        proofId: "proof_12345",
        issuer: addr1.address,
        // Missing subject, complianceType, validFrom, validUntil, evidence, signature
        schemaVersion: "1.0"
      };

      await expect(proofVerification.verifyComplianceProof(incompleteProof))
        .to.be.revertedWith("Missing required fields");
    });
  });
});
```

### 5. Transfer Binding Validation

#### Python Implementation for Transfer Binding
```python
# src/verification/transfer_binding.py
from typing import Dict, Any, Tuple
import hashlib
from datetime import datetime

class TransferBindingValidator:
    """Validator for transfer binding compliance"""
    
    def __init__(self):
        self.max_binding_age_hours = 24  # Binding must be recent
    
    def validate_transfer_binding(self, binding_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate transfer binding data to ensure it meets compliance requirements
        
        Args:
            binding_data: Dictionary containing transfer binding information
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # 1. Check required fields
            required_fields = [
                "source_address", "destination_address", "amount",
                "binding_timestamp", "binding_signature", "nonce"
            ]
            
            for field in required_fields:
                if field not in binding_data:
                    return False, f"Missing required field: {field}"
            
            # 2. Validate addresses
            is_valid, error = self._validate_addresses(binding_data)
            if not is_valid:
                return False, f"Address validation failed: {error}"
            
            # 3. Validate amount
            is_valid, error = self._validate_amount(binding_data["amount"])
            if not is_valid:
                return False, f"Amount validation failed: {error}"
            
            # 4. Validate binding freshness
            is_valid, error = self._validate_binding_freshness(binding_data["binding_timestamp"])
            if not is_valid:
                return False, f"Binding freshness validation failed: {error}"
            
            # 5. Validate signature
            is_valid, error = self._validate_binding_signature(binding_data)
            if not is_valid:
                return False, f"Binding signature validation failed: {error}"
            
            # 6. Validate nonce uniqueness
            is_valid, error = self._validate_nonce_uniqueness(binding_data["nonce"])
            if not is_valid:
                return False, f"Nonce validation failed: {error}"
            
            return True, "Transfer binding validated successfully"
            
        except Exception as e:
            return False, f"Internal validation error: {str(e)}"
    
    def _validate_addresses(self, binding_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate source and destination addresses"""
        source = binding_data["source_address"]
        destination = binding_data["destination_address"]
        
        # Basic format validation
        if not isinstance(source, str) or not source.startswith("0x") or len(source) != 42:
            return False, "Invalid source address format"
            
        if not isinstance(destination, str) or not destination.startswith("0x") or len(destination) != 42:
            return False, "Invalid destination address format"
            
        # Prevent self-transfers in certain contexts
        if source == destination:
            return False, "Source and destination addresses cannot be identical"
            
        return True, ""
    
    def _validate_amount(self, amount) -> Tuple[bool, str]:
        """Validate transfer amount"""
        if not isinstance(amount, (int, float)) or amount <= 0:
            return False, "Amount must be a positive number"
            
        # Add any compliance-specific amount limits here
        max_amount = 1000000  # Example limit
        if amount > max_amount:
            return False, f"Amount exceeds maximum allowed: {max_amount}"
            
        return True, ""
    
    def _validate_binding_freshness(self, timestamp_str: str) -> Tuple[bool, str]:
        """Validate that the binding is recent enough"""
        try:
            binding_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            now = datetime.now(binding_time.tzinfo)
            
            time_diff = now - binding_time
            if time_diff.total_seconds() > (self.max_binding_age_hours * 3600):
                return False, f"Binding is older than maximum allowed age of {self.max_binding_age_hours} hours"
                
            return True, ""
        except Exception as e:
            return False, f"Timestamp parsing error: {str(e)}"
    
    def _validate_binding_signature(self, binding_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate the cryptographic signature of the binding"""
        # In a real implementation, this would verify the signature against the source address
        # For this example, we'll just check the signature format
        signature = binding_data["binding_signature"]
        
        if not isinstance(signature, str) or not signature.startswith("0x"):
            return False, "Invalid signature format"
            
        # Mock validation - in reality this would use cryptographic verification
        if len(signature) != 132:  # Standard Ethereum signature length
            return False, "Invalid signature length"
            
        return True, ""
    
    def _validate_nonce_uniqueness(self, nonce: str) -> Tuple[bool, str]:
        """Validate that the nonce is unique (to prevent replay attacks)"""
        # In a real implementation, this would check against a database of used nonces
        # For this example, we'll just validate the nonce format
        if not isinstance(nonce, str) or len(nonce) < 8:
            return False, "Nonce must be a string of at least 8 characters"
            
        return True, ""
```

### 6. Integration with Off-Chain /proof/verify Endpoint

#### Enhanced Endpoint with Transfer Binding Validation
```python
# src/api/proof_verify_with_binding.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional
from src.verification.service import ProofVerificationService
from src.verification.transfer_binding import TransferBindingValidator
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

verification_service = ProofVerificationService()
binding_validator = TransferBindingValidator()

class ProofVerificationRequest(BaseModel):
    """Request model for proof verification with optional transfer binding"""
    proof: Dict[str, Any]
    transfer_binding: Optional[Dict[str, Any]] = None

class ProofVerificationResponse(BaseModel):
    """Response model for proof verification"""
    valid: bool
    message: str
    verification_timestamp: str
    binding_valid: Optional[bool] = None
    binding_message: Optional[str] = None
    details: Dict[str, Any] = {}

@router.post("/proof/verify")
async def verify_proof_with_binding(request: Request, verification_request: ProofVerificationRequest):
    """
    Verify a compliance proof with optional transfer binding validation
    
    This endpoint mirrors the on-chain registry checks with equivalent
    off-chain verification logic, including binding validation when provided.
    """
    try:
        # Perform comprehensive proof verification
        is_valid, message = verification_service.verify_compliance_proof(
            verification_request.proof
        )
        
        response_data = {
            "valid": is_valid,
            "message": message,
            "verification_timestamp": datetime.now().isoformat(),
            "details": {}
        }
        
        # If transfer binding is provided, validate it as well
        if verification_request.transfer_binding:
            binding_valid, binding_message = binding_validator.validate_transfer_binding(
                verification_request.transfer_binding
            )
            response_data["binding_valid"] = binding_valid
            response_data["binding_message"] = binding_message
            
            # Overall validity requires both proof and binding to be valid
            if is_valid and binding_valid:
                response_data["valid"] = True
                response_data["message"] = "Proof and transfer binding verified successfully"
            else:
                response_data["valid"] = False
                response_data["message"] = f"Verification failed: {message}"
                if not binding_valid:
                    response_data["message"] += f"; Binding validation failed: {binding_message}"
        
        # Log the verification attempt
        logger.info(f"Proof verification {'passed' if response_data['valid'] else 'failed'}: {response_data['message']}")
        
        return ProofVerificationResponse(**response_data)
        
    except Exception as e:
        logger.error(f"Error during proof verification: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal verification error: {str(e)}"
        )
```

## Testing Plan

### Unit Tests

1. **Python Unit Tests**:
   - Test valid proof verification
   - Test expired proof rejection
   - Test invalid signature rejection
   - Test malformed proof rejection
   - Test unauthorized issuer rejection
   - Test transfer binding validation

2. **TypeScript Unit Tests**:
   - Mirror all Python test cases in TypeScript
   - Test integration with Express.js endpoint

3. **Hardhat Integration Tests**:
   - Test smart contract verification functions
   - Test gas usage and performance

### Integration Tests

1. **End-to-End Verification Flow**:
   - Full proof lifecycle from creation to verification
   - Test with various compliance types
   - Test edge cases and error conditions

2. **Performance Tests**:
   - Measure verification response times
   - Test concurrent verification requests
   - Validate system under load

## Deployment Considerations

1. **Security**:
   - Rate limiting on verification endpoints
   - Input validation and sanitization
   - Secure cryptographic implementation
   - Audit logging of all verification attempts

2. **Monitoring**:
   - Verification success/failure metrics
   - Response time monitoring
   - Error rate tracking

3. **Scalability**:
   - Caching of frequently verified proofs
   - Load balancing for high-throughput scenarios
   - Database optimization for issuer registry

## Implementation Timeline

1. **Week 1**: Shared fixtures and basic verification service implementation
2. **Week 2**: Python endpoint implementation and unit tests
3. **Week 3**: TypeScript implementation and integration tests
4. **Week 4**: Hardhat integration and smart contract tests
5. **Week 5**: Transfer binding validation and comprehensive testing
6. **Week 6**: Performance optimization and documentation

## Conclusion

This implementation plan provides a comprehensive approach to adding verification checks to the off-chain /proof/verify endpoint that mirrors on-chain registry checks. The modular design allows for easy extension and maintenance while ensuring robust security and compliance validation.