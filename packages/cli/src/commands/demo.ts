import { Command } from 'commander';
import path from 'path';
import { generateProof, verifyProof } from '@clearproof/proof';
import type { ComplianceInput } from '@clearproof/proof';

/**
 * Hardcoded test input that matches the verified proof (snarkjs OK).
 *
 * Tree depths: sanctions=20 (path arrays length 20), issuer=10 (path arrays length 10).
 */
const DEMO_INPUT: ComplianceInput = {
  // === Public inputs ===
  // These values are from the verified proof (snarkjs OK!)
  sanctionsTreeRoot:
    '5165912880528319654224975632916389245447155966222261466225444971111963668911',
  issuerTreeRoot:
    '2679583485444090814519739490480408597587979659313135468790553999186444635148',
  amountTier: 2,
  transferTimestamp: 1711670400,
  jurisdictionCode: 21843, // "US" as uint16 (0x55 0x53)
  credentialCommitment:
    '3946334516594870472864654055107878340628457451312090927820290073103136770198',
  tier2Threshold: 25000,   // $250.00 in cents
  tier3Threshold: 300000,  // $3,000.00 in cents
  tier4Threshold: 1000000, // $10,000.00 in cents

  // === Private inputs: Credential preimage ===
  // commitment = Poseidon(123456789, 2, 1, 1700000000, 1800000000)
  issuerDid: '123456789',
  kycTier: 2,
  sanctionsClear: 1,
  issuedAt: 1700000000,
  expiresAt: 1800000000,

  // === Private inputs: Issuer Merkle membership proof (depth 10) ===
  // Single-issuer tree: leaf at index 0, all-zero siblings
  issuerPathElements: Array(10).fill('0'),
  issuerPathIndices: Array(10).fill('0'),

  // === Private inputs: Sanctions non-membership gap proof (depth 20) ===
  // Two-leaf tree: left=100, right=1000, query=500
  walletAddressHash: '500',
  leftKey: '100',
  rightKey: '1000',
  leftPathElements: [
    '19403184926589903505792940814745119867051186734744914561909518986732862166057',
    ...Array(19).fill('0'),
  ],
  leftPathIndices: Array(20).fill('0'),
  rightPathElements: [
    '9326983004124375216551096032771341412132084386804905225430866942582012914771',
    ...Array(19).fill('0'),
  ],
  rightPathIndices: ['1', ...Array(19).fill('0')],

  // === Private inputs: Amount ===
  actualAmount: 100000, // $1,000.00 in cents — tier 2 (between $250 and $3,000)
};

export const demoCommand = new Command('demo')
  .description('Run a 60-second demo: generate + verify a ZK compliance proof')
  .option(
    '--artifacts <dir>',
    'Path to circuit artifacts directory',
    path.resolve(__dirname, '../../../../artifacts'),
  )
  .action(async (opts: { artifacts: string }) => {
    const artifactsDir = path.resolve(opts.artifacts);
    const wasmPath = path.join(artifactsDir, 'compliance_js', 'compliance.wasm');
    const zkeyPath = path.join(artifactsDir, 'compliance_final.zkey');
    const vkeyPath = path.join(artifactsDir, 'verification_key.json');

    console.log('=== ClearProof ZK Compliance Demo ===\n');
    console.log(`Artifacts: ${artifactsDir}`);
    console.log(`Circuit:   compliance (sanctions_depth=20, issuer_depth=10)\n`);

    // --- Generate ---
    console.log('[1/2] Generating Groth16 proof...');
    const { proof, publicSignals, proofTime } = await generateProof(
      DEMO_INPUT,
      wasmPath,
      zkeyPath,
    );
    console.log(`  Proof generated in ${proofTime} ms`);
    console.log(`  Public signals (${publicSignals.length}):`);
    const signalLabels = [
      'is_compliant',
      'sar_review_flag',
      'sanctions_tree_root',
      'issuer_tree_root',
      'amount_tier',
      'transfer_timestamp',
      'jurisdiction_code',
      'credential_commitment',
      'tier2_threshold',
      'tier3_threshold',
      'tier4_threshold',
    ];
    publicSignals.forEach((s, i) => {
      const label = signalLabels[i] ?? `signal_${i}`;
      console.log(`    [${i}] ${label}: ${s}`);
    });

    // --- Verify ---
    console.log('\n[2/2] Verifying proof...');
    const result = await verifyProof(proof, publicSignals, vkeyPath);
    console.log(`  Valid:        ${result.valid}`);
    console.log(`  Compliant:    ${result.isCompliant}`);
    console.log(`  SAR Review:   ${result.sarReviewFlag}`);

    console.log(
      `\n=== Demo complete — proof ${result.valid ? 'VERIFIED' : 'FAILED'} ===`,
    );

    process.exit(result.valid ? 0 : 1);
  });
