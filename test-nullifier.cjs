const circomlibjs = require('circomlibjs');

async function testNullifier() {
  const poseidon = await circomlibjs.buildPoseidon();
  
  // These values are from the test vector
  const credentialCommitment = "1535026804069983646719003321209192566650416969181218063747264914629845874911";
  const transferIdHash = "0";
  
  console.log('Input credentialCommitment:', credentialCommitment);
  console.log('Input transferIdHash:', transferIdHash);
  
  // Calculate the expected nullifier
  const inputs = [BigInt(credentialCommitment), BigInt(transferIdHash)];
  console.log('Poseidon inputs:', inputs.map(i => i.toString()));
  
  const expectedNullifier = poseidon(inputs);
  console.log('Raw poseidon output:', expectedNullifier);
  
  // Convert the poseidon output to a single BigInt
  const expectedNullifierBigInt = poseidon.F.toObject(expectedNullifier);
  console.log('Expected nullifier (as BigInt):', expectedNullifierBigInt.toString());
  
  // The value from the test vector
  const providedNullifier = "7602049054697139437093990099647002479730647641283828197300728393733309892704";
  console.log('Provided nullifier:', providedNullifier);
  
  console.log('Match:', expectedNullifierBigInt.toString() === providedNullifier);
}

testNullifier().catch(console.error);