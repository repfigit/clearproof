import fs from 'fs';
import path from 'path';
import { generateProof, verifyProof } from '@clearproof/proof';

async function runDemoFix() {
  // Use the final test input with corrected nullifier
  const inputPath = path.resolve('./test-vector-fix/final-test-input.json');
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));

  const artifactsDir = path.resolve('./artifacts');
  const wasmPath = path.join(artifactsDir, 'compliance_js', 'compliance.wasm');
  const zkeyPath = path.join(artifactsDir, 'compliance_final.zkey');
  const vkeyPath = path.join(artifactsDir, 'verification_key.json');

  console.log('=== ClearProof ZK Compliance Demo Fix ===\n');

  try {
    // --- Generate ---
    console.log('[1/2] Generating Groth16 proof...');
    const { proof, publicSignals, proofTime } = await generateProof(
      input,
      wasmPath,
      zkeyPath,
    );
    console.log(`  Proof generated in ${proofTime} ms`);
    
    // --- Verify ---
    console.log('\n[2/2] Verifying proof...');
    const result = await verifyProof(proof, publicSignals, vkeyPath);
    console.log(`  Valid:        ${result.valid}`);
    console.log(`  Compliant:    ${result.isCompliant}`);
    console.log(`  SAR Review:   ${result.sarReviewFlag}`);

    // --- Export ---
    const outDir = path.resolve('./demo-fix-output-final');
    fs.mkdirSync(outDir, { recursive: true });
    
    fs.writeFileSync(
      path.join(outDir, 'proof.json'),
      JSON.stringify(proof, null, 2) + '\n',
    );
    fs.writeFileSync(
      path.join(outDir, 'public.json'),
      JSON.stringify(publicSignals, null, 2) + '\n',
    );
    fs.writeFileSync(
      path.join(outDir, 'input.json'),
      JSON.stringify(input, null, 2) + '\n',
    );
    fs.copyFileSync(vkeyPath, path.join(outDir, 'verification_key.json'));
    
    console.log(`\nTest vector exported to ${outDir}`);

    console.log(
      `\n=== Demo complete — proof ${result.valid ? 'VERIFIED' : 'FAILED'} ===`,
    );
    process.exit(result.valid ? 0 : 1);
  } catch (error) {
    console.error('Demo failed:', error);
    process.exit(1);
  }
}

runDemoFix();