import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import { generateProof } from '@clearproof/proof';
import type { ComplianceInput } from '@clearproof/proof';

export const proveCommand = new Command('prove')
  .description('Generate a ZK compliance proof from an input JSON file')
  .requiredOption('--input <file>', 'Path to JSON file with circuit inputs')
  .option(
    '--artifacts <dir>',
    'Path to circuit artifacts directory',
    path.resolve(__dirname, '../../../../artifacts'),
  )
  .option('--output <file>', 'Write proof JSON to this file (default: stdout)')
  .action(
    async (opts: { input: string; artifacts: string; output?: string }) => {
      const inputData: ComplianceInput = JSON.parse(
        fs.readFileSync(path.resolve(opts.input), 'utf-8'),
      );

      const artifactsDir = path.resolve(opts.artifacts);
      const wasmPath = path.join(
        artifactsDir,
        'compliance_js',
        'compliance.wasm',
      );
      const zkeyPath = path.join(artifactsDir, 'compliance_final.zkey');

      console.error(`Generating proof (artifacts: ${artifactsDir})...`);

      const result = await generateProof(inputData, wasmPath, zkeyPath);

      console.error(`Proof generated in ${result.proofTime} ms`);

      const output = JSON.stringify(
        {
          proof: result.proof,
          publicSignals: result.publicSignals,
          proofTime: result.proofTime,
        },
        null,
        2,
      );

      if (opts.output) {
        fs.writeFileSync(path.resolve(opts.output), output);
        console.error(`Written to ${opts.output}`);
      } else {
        console.log(output);
      }
    },
  );
