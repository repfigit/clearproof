import { readFileSync } from 'node:fs';
import { arch, platform } from 'node:os';
import { Command } from 'commander';

const pkg = require('../../package.json') as { version: string };

export const REPO = 'https://github.com/repfigit/clearproof';
export const SECURITY_URL = `${REPO}/security/advisories/new`;
const PROFILES = ['pilot-transfer-v1', 'pilot-transfer-v2', 'pilot-transfer-v3'];

/**
 * Keep only the non-identifying fields of a saved `clearproof doctor` result.
 * Never forward paths, stderr or unknown fields into a public issue.
 */
export function doctorSummary(raw: string): Record<string, string | boolean> {
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid doctor result');
  const summary: Record<string, string | boolean> = {};
  if (typeof value.status !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(value.status)) {
    throw new Error('Invalid doctor result');
  }
  summary.status = value.status;
  if (typeof value.reason === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value.reason)) summary.reason = value.reason;
  if (typeof value.proof_profile === 'string' && PROFILES.includes(value.proof_profile)) {
    summary.proof_profile = value.proof_profile;
  }
  if (typeof value.manifest_digest === 'string' && /^[a-f0-9]{64}$/.test(value.manifest_digest)) {
    summary.manifest_digest = value.manifest_digest;
  }
  for (const key of ['current_profile_supported', 'policy_schema_supported']) {
    if (typeof value[key] === 'boolean') summary[key] = value[key] as boolean;
  }
  return summary;
}

/** Versions and platform only: no hostname, user, paths or environment variables. */
export function environment(): string {
  return [`@clearproof/cli ${pkg.version}`, `Node ${process.version}`, `${platform()} ${arch()}`].join('\n');
}

export function issueUrl(kind: 'bug' | 'feature', title: string | undefined, doctor?: Record<string, string | boolean>): string {
  const params = new URLSearchParams();
  if (kind === 'bug') {
    params.set('template', 'bug_report.yml');
    params.set('title', `[Bug]: ${title ?? ''}`);
    params.set('version', pkg.version);
    const lines = [environment()];
    if (doctor) lines.push('', 'clearproof doctor:', JSON.stringify(doctor, null, 2));
    params.set('environment', lines.join('\n'));
  } else {
    params.set('template', 'feature_request.yml');
    params.set('title', `[Feature]: ${title ?? ''}`);
  }
  return `${REPO}/issues/new?${params.toString()}`;
}

export const reportCommand = new Command('report')
  .description('Print a pre-filled GitHub issue link with versions and platform; nothing is sent')
  .option('--kind <kind>', 'bug or feature', 'bug')
  .option('--title <title>', 'Short issue title')
  .option('--doctor <file>', 'Saved `clearproof doctor` JSON to summarize (bug reports only)')
  .option('--json', 'Print {url, environment} as JSON for scripts and agents')
  .action((options: { kind: string; title?: string; doctor?: string; json?: boolean }) => {
    try {
      if (options.kind !== 'bug' && options.kind !== 'feature') throw new Error('--kind must be bug or feature');
      if (options.title !== undefined && (options.title.length > 200 || /[\r\n]/.test(options.title))) {
        throw new Error('--title must be one line of at most 200 characters');
      }
      if (options.doctor && options.kind !== 'bug') throw new Error('--doctor applies to bug reports only');
      const doctor = options.doctor ? doctorSummary(readFileSync(options.doctor, 'utf8')) : undefined;
      const url = issueUrl(options.kind, options.title, doctor);
      if (options.json) {
        process.stdout.write(JSON.stringify({ url, environment: environment(), security: SECURITY_URL }) + '\n');
      } else {
        process.stdout.write(
          `Open this link to review and submit the issue:\n${url}\n\n` +
            'Check the pre-filled text before submitting. Never include personal data, keys or credentials.\n' +
            `Security vulnerabilities: report privately at ${SECURITY_URL}\n`,
        );
      }
    } catch (error) {
      process.stderr.write(`clearproof report: ${(error as Error).message}\n`);
      process.exitCode = 1;
    }
  });
