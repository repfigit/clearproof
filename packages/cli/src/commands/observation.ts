import { Command } from 'commander';
import { createObservation, readObservation, reportObservationCohort, listObservations } from '@clearproof/proof';
import { readPrivateInput, reportEndpoint } from '../api-client.js';

const clients = { create: createObservation, read: readObservation, report: reportObservationCohort, list: listObservations };
const paths = { create: '/pilot/proof/observe', read: '/pilot/proof/observations/read',
  report: '/pilot/proof/observations/report', list: '/pilot/proof/observations/list' } as const;

export const observationCommand = new Command('observation').description('Create or read non-enforcing pilot observations');
for (const operation of ['create', 'read', 'report', 'list'] as const) {
  observationCommand.command(operation)
    .description('Read private request JSON from stdin; print observations or reports without authorizing a transfer')
    .requiredOption('--api-url <origin>', 'Operator-selected API origin (HTTPS, or loopback HTTP for local evaluation)')
    .action(async (options: { apiUrl: string }) => {
      try {
        reportEndpoint(options.apiUrl, paths[operation]);
        const token = process.env.CLEARPROOF_API_TOKEN ?? '';
        if (!token) throw new Error('API token required');
        const report = await clients[operation](
          options.apiUrl, token, await readPrivateInput(process.stdin));
        process.stdout.write(JSON.stringify(report) + '\n');
        // Success means the observation operation succeeded, regardless of its policy outcome.
      } catch {
        process.stderr.write('Observation request failed. Check API origin, token, permissions and input.\n');
        process.exitCode = 2;
      }
    });
}
