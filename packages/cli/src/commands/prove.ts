import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import { generateProof } from '@clearproof/proof';
import type { ComplianceInput } from '@clearproof/proof';
import { defaultArtifactsDir, requireArtifactPaths } from '../legacy-artifacts.js';
import { parseComplianceInput } from '../input-guards.js';

export const proveCommand = new Command('prove')
  .description('Legacy 16-signal demo profile: generate a proof locally from an input JSON file (not pilot-transfer-v3)')
  .requiredOption('--input <file>', 'Path to JSON file with legacy circuit inputs')
  .option(
    '--artifacts <dir>',
    'Path to legacy circuit artifacts directory (none are bundled)',
    defaultArtifactsDir(),
  )
  .option('--output <file>', 'Write proof JSON to this file (default: stdout)')
  .action(
    async (opts: { input: string; artifacts: string; output?: string }) => {
      const artifactsDir = path.resolve(opts.artifacts);
      let selected;
      let inputData: ComplianceInput;
      try {
        selected = requireArtifactPaths(artifactsDir);
        inputData = parseComplianceInput(fs.readFileSync(path.resolve(opts.input), 'utf-8'));
      } catch (error) { console.error((error as Error).message); process.exitCode = 2; return; }
      const { wasmPath, zkeyPath } = selected;

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
