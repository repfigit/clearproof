import { Command } from 'commander';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { generateProof, verifyProof, getThresholds } from '@clearproof/proof';
import type { ComplianceInput } from '@clearproof/proof';

import { defaultArtifactsDir, requireArtifactPaths } from '../legacy-artifacts.js';
export { defaultArtifactsDir, resolveArtifactPaths } from '../legacy-artifacts.js';

/**
 * Zero-subtree hashes for a Poseidon(2) Merkle tree: Z[0] = 0 (empty leaf),
 * Z[i+1] = Poseidon(Z[i], Z[i]). Used as siblings for untouched subtrees.
 */
const ZERO_SUBTREE = [
  '0',
  '14744269619966411208579211824598458697587494354926760081771325075741142829156',
  '7423237065226347324353380772367382631490014989348495481811164164159255474657',
  '11286972368698509976183087595462810875513684078608517520839298933882497716792',
  '3607627140608796879659380071776844901612302623152076817094415224584923813162',
  '19712377064642672829441595136074946683621277828620209496774504837737984048981',
  '20775607673010627194014556968476266066927294572720319469184847051418138353016',
  '3396914609616007258851405644437304192397291162432396347162513310381425243293',
  '21551820661461729022865262380882070649935529853313286572328683688269863701601',
  '6573136701248752079028194407151022595060682063033565181951145966236778420039',
  '12413880268183407374852357075976609371175688755676981206018884971008854919922',
  '14271763308400718165336499097156975241954733520325982997864342600795471836726',
  '20066985985293572387227381049700832219069292839614107140851619262827735677018',
  '9394776414966240069580838672673694685292165040808226440647796406499139370960',
  '11331146992410411304059858900317123658895005918277453009197229807340014528524',
  '15819538789928229930262697811477882737253464456578333862691129291651619515538',
  '19217088683336594659449020493828377907203207941212636669271704950158751593251',
  '21035245323335827719745544373081896983162834604456827698288649288827293579666',
  '6939770416153240137322503476966641397417391950902474480970945462551409848591',
  '10941962436777715901943463195175331263348098796018438960955633645115732864202',
];

/**
 * Hardcoded test input that produces a valid proof under the current circuit
 * hashing scheme (regenerated 2026-05-21 after the sanctions-leaf domain-hash
 * fix; values verified against circomlibjs Poseidon):
 *
 *   sanctions leaf  = Poseidon(1, addr_int)   — tree sorted by hash value
 *   issuer leaf     = Poseidon(2, issuer_did)
 *   internal nodes  = Poseidon(left, right)
 *   commitment      = Poseidon(did, kyc_tier, sanctions_clear, issued, expires)
 *   nullifier       = Poseidon(commitment, transfer_id_hash)
 *
 * Demo sanctions tree (depth 20): two leaves at indices 0 and 1 —
 * Poseidon(1, 1) and Poseidon(1, 412). Demo wallet is addr int 101; its
 * domain-separated hash Poseidon(1, 101) falls strictly between the two
 * leaf hashes (all < 2^252 for the circuit's LessThan(252) range checks).
 * Issuer tree (depth 10): single issuer leaf at index 0, zero subtrees above.
 */
const DEMO_JURISDICTION = 'US';
const DEMO_THRESHOLDS = getThresholds(DEMO_JURISDICTION);

const DEMO_INPUT: ComplianceInput = {
  // === Public inputs ===
  sanctionsTreeRoot:
    '19485189886927225448826174452960148901400409437721799234319594596150284213144',
  issuerTreeRoot:
    '13669355367237519159663497518513536058941277231317989217194400446243591384968',
  amountTier: 2,
  transferTimestamp: 1711670400,
  jurisdictionCode: 21843, // "US" as uint16 (0x55 0x53)
  credentialCommitment:
    '3946334516594870472864654055107878340628457451312090927820290073103136770198',
  tier2Threshold: DEMO_THRESHOLDS.tier2,
  tier3Threshold: DEMO_THRESHOLDS.tier3,
  tier4Threshold: DEMO_THRESHOLDS.tier4,

  // === Private inputs: Credential preimage ===
  // commitment = Poseidon(123456789, 2, 1, 1700000000, 1800000000)
  issuerDid: '123456789',
  kycTier: 2,
  sanctionsClear: 1,
  issuedAt: 1700000000,
  expiresAt: 1800000000,

  // === Private inputs: Issuer Merkle membership proof (depth 10) ===
  // Leaf = Poseidon(2, issuerDid) at index 0; siblings are zero subtrees
  issuerPathElements: ZERO_SUBTREE.slice(0, 10),
  issuerPathIndices: Array(10).fill('0'),

  // === Private inputs: Sanctions non-membership gap proof (depth 20) ===
  // Keys ARE the domain-separated leaves: left = Poseidon(1, 1) at index 0,
  // right = Poseidon(1, 412) at index 1, query = Poseidon(1, 101) between them.
  walletAddressHash:
    '2570728153758525455068681255560397293445847326980545556667885052648074786431',
  leftKey:
    '217234377348884654691879377518794323857294947151490278790710809376325639809',
  rightKey:
    '4767571459625676338886140567802060826627379438215026793278462573473607028657',
  // Left proof (index 0): level-0 sibling is the right leaf, then zero subtrees
  leftPathElements: [
    '4767571459625676338886140567802060826627379438215026793278462573473607028657',
    ...ZERO_SUBTREE.slice(1, 20),
  ],
  leftPathIndices: Array(20).fill('0'),
  // Right proof (index 1): level-0 sibling is the left leaf, then zero subtrees
  rightPathElements: [
    '217234377348884654691879377518794323857294947151490278790710809376325639809',
    ...ZERO_SUBTREE.slice(1, 20),
  ],
  rightPathIndices: ['1', ...Array(19).fill('0')],

  // === Public inputs: Domain binding (zeros for demo — not deployed to chain) ===
  domainChainId: 0,
  domainContractHash: '0',
  transferIdHash: '0',
  // nullifier = Poseidon(credentialCommitment, transferIdHash=0)
  credentialNullifier:
    '13240535717232054844213623400351701779147624874153591729536053257199079312660',
  proofExpiresAt: 1711670400 + 300, // transfer_timestamp + 300s TTL

  // === Private inputs: Amount ===
  actualAmount: 1000, // $1,000 USD — tier 2 (between $250 and $3,000)
};

export const demoCommand = new Command('demo')
  .description('Run a 60-second demo: generate + verify a ZK compliance proof')
  .option(
    '--artifacts <dir>',
    'Path to circuit artifacts directory',
    defaultArtifactsDir(),
  )
  .option(
    '--export <dir>',
    'Also write the parity test vector (proof/public/input/vkey/MANIFEST) to this directory',
  )
  .action(async (opts: { artifacts: string; export?: string }) => {
    const artifactsDir = path.resolve(opts.artifacts);
    let selected;
    try { selected = requireArtifactPaths(artifactsDir); }
    catch (error) { console.error((error as Error).message); process.exitCode = 2; return; }
    const { wasmPath, zkeyPath, vkeyPath } = selected;

    console.log('=== Clearproof legacy cryptographic demo (development only) ===\n');
    console.log('This demo does not authorize a transfer or establish production compliance.');
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
      'domain_chain_id',
      'domain_contract_hash',
      'transfer_id_hash',
      'credential_nullifier',
      'proof_expires_at',
    ];
    publicSignals.forEach((s: string, i: number) => {
      const label = signalLabels[i] ?? `signal_${i}`;
      console.log(`    [${i}] ${label}: ${s}`);
    });

    // --- Verify ---
    console.log('\n[2/2] Verifying proof...');
    const result = await verifyProof(proof, publicSignals, vkeyPath);
    console.log(`  Valid:        ${result.valid}`);
    console.log(`  Compliant:    ${result.isCompliant}`);
    console.log(`  SAR Review:   ${result.sarReviewFlag}`);

    // --- Optional: export parity test vector ---
    if (opts.export) {
      const outDir = path.resolve(opts.export);
      fs.mkdirSync(outDir, { recursive: true });

      const sha256 = (p: string) =>
        crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

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
        JSON.stringify(DEMO_INPUT, null, 2) + '\n',
      );
      fs.copyFileSync(vkeyPath, path.join(outDir, 'verification_key.json'));

      const manifest = {
        description:
          'clearproof compliance-circuit parity test vector (off-chain + on-chain verification)',
        circuit: 'compliance',
        proofSystem: 'groth16',
        curve: 'bn128',
        devKeysOnly: true,
        warning:
          'Generated from a single-party dev trusted setup. NOT valid for production.',
        artifacts: {
          wasm_sha256: sha256(wasmPath),
          zkey_sha256: sha256(zkeyPath),
          vkey_sha256: sha256(vkeyPath),
        },
        toolchain: {
          circom: '2.2.2',
          snarkjs: '0.7.6',
          ptau: 'powersOfTau28_hez_final_18 (sha256-verified Hermez)',
        },
      };
      fs.writeFileSync(
        path.join(outDir, 'MANIFEST.json'),
        JSON.stringify(manifest, null, 2) + '\n',
      );
      console.log(`\nParity vector exported to ${outDir}`);
    }

    console.log(
      `\n=== Demo complete — proof ${result.valid ? 'VERIFIED' : 'FAILED'} ===`,
    );

    process.exit(result.valid ? 0 : 1);
  });
