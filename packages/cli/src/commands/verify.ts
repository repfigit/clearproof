import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import { verifyProof } from '@clearproof/proof';

export const verifyCommand = new Command('verify')
  .description('Verify a ZK compliance proof')
  .requiredOption('--proof <file>', 'Path to proof JSON (output of "prove")')
  .option(
    '--artifacts <dir>',
    'Path to circuit artifacts directory',
    path.resolve(__dirname, '../../../../artifacts'),
  )
  .action(async (opts: { proof: string; artifacts: string }) => {
    const data = JSON.parse(
      fs.readFileSync(path.resolve(opts.proof), 'utf-8'),
    );

    const artifactsDir = path.resolve(opts.artifacts);
    const vkeyPath = path.join(artifactsDir, 'verification_key.json');

    console.error(`Verifying proof (vkey: ${vkeyPath})...`);

    const result = await verifyProof(data.proof, data.publicSignals, vkeyPath);

    console.log(
      JSON.stringify(
        {
          valid: result.valid,
          isCompliant: result.isCompliant,
          sarReviewFlag: result.sarReviewFlag,
          publicSignals: result.publicSignals,
        },
        null,
        2,
      ),
    );

    process.exit(result.valid ? 0 : 1);
  });
