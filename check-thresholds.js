import fs from 'fs';
import { thresholdsMatchJurisdiction, decodeJurisdiction, getThresholds } from '@clearproof/proof/dist/thresholds.js';

async function checkThresholds() {
  const publicSignals = JSON.parse(fs.readFileSync('./demo-fix-output/public.json', 'utf-8'));
  
  console.log('=== Checking Thresholds ===\n');
  
  // Log the jurisdiction code from signal 6
  const jurisdictionCode = publicSignals[6];
  console.log('Jurisdiction code (signal 6):', jurisdictionCode);
  
  // Decode the jurisdiction
  const jurisdiction = decodeJurisdiction(jurisdictionCode);
  console.log('Decoded jurisdiction:', jurisdiction);
  
  // Get expected thresholds
  if (jurisdiction) {
    const expected = getThresholds(jurisdiction);
    console.log('Expected thresholds for', jurisdiction, ':', expected);
  }
  
  // Check if thresholds match
  const match = thresholdsMatchJurisdiction(publicSignals);
  console.log('Thresholds match:', match);
  
  // Log the actual threshold values from the public signals
  console.log('Actual thresholds from signals:');
  console.log('  tier2 (signal 8):', publicSignals[8]);
  console.log('  tier3 (signal 9):', publicSignals[9]);
  console.log('  tier4 (signal 10):', publicSignals[10]);
}

checkThresholds().catch(console.error);