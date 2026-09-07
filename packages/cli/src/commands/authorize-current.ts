import { Command } from 'commander';
import { authorizeCurrentProof } from '@clearproof/proof';
import { readPrivateInput, reportEndpoint } from '../api-client.js';

export const authorizeCurrentCommand = new Command('authorize-current')
  .description('Explicitly consume a local pilot authorization, or recover its same-key receipt; no fund execution')
  .requiredOption('--api-url <origin>', 'Operator-selected API origin (HTTPS, or loopback HTTP for local evaluation)')
  .action(async (options: { apiUrl: string }) => {
    try {
      reportEndpoint(options.apiUrl, '/pilot/proof/authorize');
      const token = process.env.CLEARPROOF_API_TOKEN ?? '';
      if (!token) throw new Error('API token required');
      const report = await authorizeCurrentProof(options.apiUrl, token, await readPrivateInput(process.stdin));
      process.stdout.write(JSON.stringify(report) + '\n');
    } catch {
      process.stderr.write('Authorization response unavailable or rejected. Check configuration and input; retry only the same request and idempotency key.\n');
      process.exitCode = 2;
    }
  });
