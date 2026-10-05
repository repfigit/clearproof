import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import { verifyProof } from '@clearproof/proof';
import { defaultArtifactsDir, requireArtifactPaths } from '../legacy-artifacts.js';
import { parseProofFile } from '../input-guards.js';

export const verifyCommand = new Command('verify')
  .description('Verify a ZK compliance proof')
  .requiredOption('--proof <file>', 'Path to proof JSON (output of "prove")')
  .option(
    '--artifacts <dir>',
    'Path to circuit artifacts directory',
    defaultArtifactsDir(),
  )
  .action(async (opts: { proof: string; artifacts: string }) => {
    const artifactsDir = path.resolve(opts.artifacts);
    let vkeyPath: string;
    let data: { proof: object; publicSignals: string[] };
    try {
      ({ vkeyPath } = requireArtifactPaths(artifactsDir, ['vkeyPath']));
      data = parseProofFile(fs.readFileSync(path.resolve(opts.proof), 'utf-8'));
    } catch (error) { console.error((error as Error).message); process.exitCode = 2; return; }

    console.error(`Verifying proof (vkey: ${vkeyPath})...`);

    const result = await verifyProof(data.proof, data.publicSignals, vkeyPath);

    // Circuit outputs are only meaningful for an accepted proof; never print them beside valid: false.
    console.log(
      JSON.stringify(
        {
          valid: result.valid,
          rejectionReasons: result.rejectionReasons,
          isCompliant: result.valid && result.isCompliant,
          sarReviewFlag: result.valid ? result.sarReviewFlag : null,
          publicSignals: result.publicSignals,
        },
        null,
        2,
      ),
    );

    process.exit(result.valid ? 0 : 1);
  });
