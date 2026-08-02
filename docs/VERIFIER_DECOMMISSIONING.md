# Verifier Decommissioning Guide

This document outlines the process for safely decommissioning retired verifiers in the clearproof system.

## Overview

With the introduction of the `VerifierRouter`, verifiers can now be swapped without redeploying the entire `ComplianceRegistry`. This allows for smooth transitions between verifier versions while maintaining security and preventing stranded proofs.

## Decommissioning Process

### 1. Register New Verifier

1. Deploy the new verifier contract
2. Register it with the `VerifierRouter` using a unique selector
3. Wait for the timelock period to expire
4. Activate the new verifier

### 2. Update ComplianceRegistry

1. Update the `ComplianceRegistry` to use the new verifier selector
2. Verify that proofs are being verified correctly with the new verifier

### 3. Schedule Retirement of Old Verifier

1. Schedule retirement of the old verifier using `scheduleRetirement`
2. Wait for the timelock period to expire
3. Complete the retirement using `completeRetirement`

### 4. Monitor for Stranded Proofs

1. Monitor the system for any proofs that might still reference the retired verifier
2. Ensure that all in-flight proofs have been processed before fully retiring the verifier

### 5. Emergency Procedures

1. If issues are detected with the new verifier, the emergency stop can be used to disable it immediately
2. The old verifier can be reactivated if needed (though this should be done with caution)

## Runbook

### Normal Decommissioning

1. Deploy new verifier:
   ```
   const newVerifier = await NewVerifierFactory.deploy();
   await newVerifier.waitForDeployment();
   ```

2. Register with router:
   ```
   const selector = ethers.keccak256(ethers.toUtf8Bytes("new-verifier-v1"));
   await verifierRouter.registerVerifier(selector, await newVerifier.getAddress(), "New Verifier v1");
   ```

3. Wait timelock period (24 hours):
   ```
   // Wait 24 hours
   ```

4. Activate new verifier:
   ```
   await verifierRouter.activateVerifier(selector, "New Verifier v1");
   ```

5. Update ComplianceRegistry:
   ```
   await complianceRegistry.setVerifierSelector(selector);
   ```

6. Schedule retirement of old verifier:
   ```
   const oldSelector = ethers.keccak256(ethers.toUtf8Bytes("old-verifier-v1"));
   await verifierRouter.scheduleRetirement(oldSelector);
   ```

7. Wait timelock period (24 hours):
   ```
   // Wait 24 hours
   ```

8. Complete retirement:
   ```
   await verifierRouter.completeRetirement(oldSelector);
   ```

### Emergency Decommissioning

1. Disable problematic verifier:
   ```
   await verifierRouter.disableVerifier(problematicSelector);
   ```

2. Revert to previous verifier:
   ```
   await complianceRegistry.setVerifierSelector(backupSelector);
   ```

## Security Considerations

1. Always use the timelock mechanism to prevent accidental changes
2. Monitor for any proofs that might be stranded during the transition
3. Keep detailed records of verifier versions and their retirement dates
4. Test thoroughly in a staging environment before making changes in production

## Historical Retirements

The `deployments/sepolia.json` file contains a record of previous verifier retirements:

```json
{
  "previous": {
    "Groth16Verifier": "0x8ab9F1d446967BdE39bfE81B681E727EdcdF76Da",
    "ComplianceRegistry": "0xD038f2C6Ea7b414356Dc74C317cAE35Bc1c2b78a",
    "retiredAt": "2026-07-20T16:28:02.099Z",
    "reason": "Apache-2.0 verifier redeploy (ADR 0001 Option B)"
  }
}
```

Keep this file updated with each verifier retirement for audit purposes.