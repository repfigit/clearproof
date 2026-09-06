import { Command } from 'commander';
import { Readable } from 'node:stream';

const INPUT_LIMIT = 1024 * 1024;
const OUTPUT_LIMIT = 2 * 1024 * 1024;

export function policyEndpoint(base: string, stored: boolean): URL {
  const url = new URL(base);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new Error('Invalid API origin');
  }
  url.pathname = stored ? '/pilot/policy/diff/stored' : '/pilot/policy/diff';
  return url;
}

export async function readPolicyInput(input: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  const timeout = setTimeout(() => input.destroy(new Error('Input timeout')), 10_000);
  try {
    for await (const chunk of input) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > INPUT_LIMIT) throw new Error('Input limit exceeded');
      chunks.push(bytes);
    }
    if (!size) throw new Error('Empty input');
    return Buffer.concat(chunks);
  } finally {
    clearTimeout(timeout);
  }
}

export async function policyDiff(base: string, token: string, stored: boolean, input: Buffer): Promise<string> {
  if (!token || /[\s\x00-\x1f\x7f]/.test(token) || input.length === 0 || input.length > INPUT_LIMIT) {
    throw new Error('Invalid comparison configuration');
  }
  const response = await fetch(policyEndpoint(base, stored), {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: new Uint8Array(input),
    redirect: 'error',
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error('Comparison request rejected');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > OUTPUT_LIMIT) throw new Error('Response limit exceeded');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (report?.schema_version !== 'clearproof-policy-diff-v1' || report.mode !== 'counterfactual' ||
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
