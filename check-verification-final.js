import fs from 'fs';
import path from 'path';
import { verifyProof } from '@clearproof/proof';

async function checkVerification() {
  const publicSignals = JSON.parse(fs.readFileSync('./demo-fix-output-final/public.json', 'utf-8'));
  const proof = JSON.parse(fs.readFileSync('./demo-fix-output-final/proof.json', 'utf-8'));
  const vkeyPath = './demo-fix-output-final/verification_key.json';

  console.log('=== Checking Verification ===\n');

  try {
    const result = await verifyProof(proof, publicSignals, vkeyPath);
    console.log(`  Valid:        ${result.valid}`);
    console.log(`  Proof Valid:  ${result.proofValid}`);
    console.log(`  Thresholds Bound: ${result.thresholdsBound}`);
    console.log(`  Rejection Reasons: ${result.rejectionReasons.join(', ')}`);
    console.log(`  Compliant:    ${result.isCompliant}`);
    console.log(`  SAR Review:   ${result.sarReviewFlag}`);
  } catch (error) {
    console.error('Verification check failed:', error);
  }
}

checkVerification();