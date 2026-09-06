import { Command } from 'commander';
import { createObservation, readObservation } from '@clearproof/proof';
import { readPrivateInput, reportEndpoint } from '../api-client.js';

export const observationCommand = new Command('observation').description('Create or read non-enforcing pilot observations');
for (const operation of ['create', 'read'] as const) {
  observationCommand.command(operation)
    .description('Read private request JSON from stdin; print a retained observation, never an authorization')
    .requiredOption('--api-url <origin>', 'Operator-selected API origin (HTTPS, or loopback HTTP for local evaluation)')
    .action(async (options: { apiUrl: string }) => {
      try {
        reportEndpoint(options.apiUrl, operation === 'create' ? '/pilot/proof/observe' : '/pilot/proof/observations/read');
        const token = process.env.CLEARPROOF_API_TOKEN ?? '';
        if (!token) throw new Error('API token required');
        const report = await (operation === 'create' ? createObservation : readObservation)(
          options.apiUrl, token, await readPrivateInput(process.stdin));
        process.stdout.write(JSON.stringify(report) + '\n');
        // Success means the observation operation succeeded, regardless of its policy outcome.
      } catch {
        process.stderr.write('Observation request failed. Check API origin, token, permissions and input.\n');
        process.exitCode = 2;
      }
    });
}
