import fs from 'fs';
import { buildPoseidon } from 'circomlibjs';

async function testNullifier() {
  const poseidon = await buildPoseidon();
  
  // These values are from the test vector
  const credentialCommitment = "1535026804069983646719003321209192566650416969181218063747264914629845874911";
  const transferIdHash = "0";
  
  // Calculate the expected nullifier
  const expectedNullifier = poseidon([BigInt(credentialCommitment), BigInt(transferIdHash)]);
  console.log('Expected nullifier:', expectedNullifier.toString());
  
  // The value from the test vector
  const providedNullifier = "7602049054697139437093990099647002479730647641283828197300728393733309892704";
  console.log('Provided nullifier:', providedNullifier);
  
  console.log('Match:', expectedNullifier.toString() === providedNullifier);
}

testNullifier().catch(console.error);