import { spawn } from 'node:child_process';
import { Command } from 'commander';

export const verifyHistoryCommand = new Command('verify-history')
  .description('Review encrypted history offline; supply the 64-hex reviewer key on stdin')
  .requiredOption('--python <executable>', 'Python environment with Clearproof installed')
  .requiredOption('--bundle <file>', 'Encrypted history export')
  .requiredOption('--trust <file>', 'Independently approved reviewer configuration')
  .requiredOption('--artifacts <directory>', 'Locally pinned artifact directory')
  .requiredOption('--runtime <file>', 'Pinned snarkjs JavaScript bundle')
  .requiredOption('--node <executable>', 'Trusted Node executable for pairing')
  .option('--verified-at <epoch>', 'Reviewer time; defaults to the current clock')
  .action(async (options: {
    python: string; bundle: string; trust: string; artifacts: string;
    runtime: string; node: string; verifiedAt?: string;
  }) => {
    const args = ['-m', 'src.prover.history_cli',
      '--bundle', options.bundle, '--trust', options.trust,
      '--artifacts', options.artifacts, '--runtime', options.runtime, '--node', options.node];
    if (options.verifiedAt !== undefined) args.push('--verified-at', options.verifiedAt);
    await new Promise<void>((resolve) => {
      const child = spawn(options.python, args, { stdio: 'inherit', shell: false });
      child.once('error', () => {
        console.log(JSON.stringify({ schema_version: 'clearproof-history-report-v1',
          scope: 'recorded-local-policy-decision', outcome: 'indeterminate',
          reasons: ['history_runtime_unavailable'] }));
        process.exitCode = 2;
        resolve();
      });
      child.once('close', (code) => {
        process.exitCode = code === 0 || code === 1 || code === 2 ? code : 2;
        resolve();
      });
    });
  });
