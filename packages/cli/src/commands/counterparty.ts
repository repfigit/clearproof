import { spawn } from 'node:child_process';
import { Command } from 'commander';

export const counterpartyCommand = new Command('counterparty')
  .description('Simulate a local bilateral disposition; supply recipient keys as JSON on stdin')
  .requiredOption('--python <executable>', 'Python environment with Clearproof installed')
  .requiredOption('--request <file>', 'Encrypted local bilateral request')
  .requiredOption('--trust <file>', 'Independent recipient transfer, context and public authorities')
  .requiredOption('--observed-at <epoch>', 'Declared local simulation clock')
  .option('--behavior <behavior>', 'accept, reject, request-information or timeout', 'accept')
  .option('--deadline <epoch>', 'Local timeout deadline')
  .action(async (options: {
    python: string; request: string; trust: string; observedAt: string; behavior: string; deadline?: string;
  }) => {
    const args = ['-m', 'src.protocol.bridges.pilot_bilateral_cli',
      '--request', options.request, '--trust', options.trust,
      '--observed-at', options.observedAt, '--behavior', options.behavior];
    if (options.deadline !== undefined) args.push('--deadline', options.deadline);
    await new Promise<void>((resolve) => {
      const child = spawn(options.python, args, { stdio: 'inherit', shell: false });
      child.once('error', () => {
        console.log(JSON.stringify({ schema_version: 'clearproof-local-counterparty-error-v1',
          source_authenticity: 'local-simulator', outcome: 'invalid-input',
          reason: 'local-counterparty-runtime-unavailable', authorization: 'not-created', execution: 'not-requested' }));
        process.exitCode = 2;
        resolve();
      });
      child.once('close', (code) => {
        process.exitCode = code === 0 ? 0 : 2;
        resolve();
      });
    });
  });
