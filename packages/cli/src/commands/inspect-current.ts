import { Command } from 'commander';
import { inspectCurrentProof } from '@clearproof/proof';
import { readPrivateInput, reportEndpoint } from '../api-client.js';

export const inspectCurrentCommand = new Command('inspect-current')
  .description('Read pilot proof JSON from stdin and inspect current state through the authenticated API')
  .requiredOption('--api-url <origin>', 'Operator-selected API origin (HTTPS, or loopback HTTP for local evaluation)')
  .action(async (options: { apiUrl: string }) => {
    try {
      reportEndpoint(options.apiUrl, '/pilot/proof/inspect');
      const token = process.env.CLEARPROOF_API_TOKEN ?? '';
      if (!token) throw new Error('API token is required');
      const report = await inspectCurrentProof(options.apiUrl, token, await readPrivateInput(process.stdin));
      process.stdout.write(JSON.stringify(report) + '\n');
      process.exitCode = report.cryptographic_valid ? 0 : 1;
    } catch {
      process.stderr.write('Current proof inspection failed. Check API origin, token, permissions and input.\n');
      process.exitCode = 2;
    }
  });
