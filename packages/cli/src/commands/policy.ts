import { Command } from 'commander';
import { readPrivateInput, reportEndpoint, requestReport } from '../api-client.js';

export const readPolicyInput = readPrivateInput;
export function policyEndpoint(base: string, stored: boolean): URL {
  return reportEndpoint(base, stored ? '/pilot/policy/diff/stored' : '/pilot/policy/diff');
}
export async function policyDiff(base: string, token: string, stored: boolean, input: Buffer): Promise<string> {
  const report = await requestReport(base, token, stored ? '/pilot/policy/diff/stored' : '/pilot/policy/diff', input);
  if (report.schema_version !== 'clearproof-policy-diff-v1' || report.mode !== 'counterfactual' ||
      !Array.isArray(report.cases)) throw new Error('Invalid comparison response');
  return JSON.stringify(report);
}

export const policyCommand = new Command('policy').description('Review policy behavior through the authenticated API');
policyCommand.command('diff')
  .description('Read comparison JSON from stdin; write a tenant-private counterfactual report')
  .requiredOption('--api-url <origin>', 'Operator-selected API origin (HTTPS, or loopback HTTP for local evaluation)')
  .option('--stored', 'Input contains retained policy/case digests instead of supplied snapshots', false)
  .action(async (options: { apiUrl: string; stored: boolean }) => {
    try {
      // Validate destination and credentials before reading confidential input.
      policyEndpoint(options.apiUrl, options.stored);
      const token = process.env.CLEARPROOF_API_TOKEN ?? '';
      if (!token) throw new Error('API token is required');
      const input = await readPolicyInput(process.stdin);
      process.stdout.write(await policyDiff(options.apiUrl, token, options.stored, input) + '\n');
    } catch {
      // Never echo submitted values, bearer tokens, response bodies or URLs on failure.
      process.stderr.write('Policy comparison failed. Check API origin, token, permissions and input.\n');
      process.exitCode = 1;
    }
  });
