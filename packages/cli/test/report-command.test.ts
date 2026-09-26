import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
let dir: string;
const originalExitCode = process.exitCode;
beforeEach(() => {
  vi.resetModules();
  output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  errors = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  process.exitCode = 0;
  dir = mkdtempSync(join(tmpdir(), 'clearproof-report-'));
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = originalExitCode;
  rmSync(dir, { recursive: true, force: true });
});
async function run(args: string[]) {
  const { reportCommand } = await import('../src/commands/report.js');
  // Commander keeps option values between parses of the same instance; import a fresh module each time.
  await reportCommand.parseAsync(args, { from: 'user' });
}
const printed = () => output.mock.calls.map((call) => call[0]).join('');
const params = (url: string) => new URL(url).searchParams;
const doctorFile = (value: unknown) => {
  const file = join(dir, 'doctor.json');
  writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
  return file;
};

describe('doctorSummary', () => {
  it('keeps only whitelisted, well-formed fields', async () => {
    const { doctorSummary } = await import('../src/commands/report.js');
    expect(doctorSummary(JSON.stringify({
      status: 'development_unapproved', proof_profile: 'pilot-transfer-v3', manifest_digest: 'a'.repeat(64),
      current_profile_supported: true, policy_schema_supported: false, reason: 'ok_reason',
      artifacts_path: '/home/someone/private', extra: 'SYNTHETIC-PRIVATE',
    }))).toEqual({
      status: 'development_unapproved', reason: 'ok_reason', proof_profile: 'pilot-transfer-v3',
      manifest_digest: 'a'.repeat(64), current_profile_supported: true, policy_schema_supported: false,
    });
  });

  it('drops malformed optional fields', async () => {
    const { doctorSummary } = await import('../src/commands/report.js');
    expect(doctorSummary(JSON.stringify({
      status: 'rejected', reason: 'Has Spaces', proof_profile: 'unknown', manifest_digest: 'xyz',
      current_profile_supported: 'yes',
    }))).toEqual({ status: 'rejected' });
  });

  it.each(['null', '[]', '"text"', '{}', '{"status":"Bad Status"}', '{"status":7}'])('rejects %s', async (raw) => {
    const { doctorSummary } = await import('../src/commands/report.js');
    expect(() => doctorSummary(raw)).toThrow('Invalid doctor result');
  });
});

describe('issueUrl and environment', () => {
  it('builds a bug report link with versions and platform only', async () => {
    const { issueUrl, environment } = await import('../src/commands/report.js');
    const env = environment();
    expect(env).toMatch(/^@clearproof\/cli \d+\.\d+\.\d+\nNode v\d+/);
    const url = issueUrl('bug', 'Proof rejected');
    expect(url.startsWith('https://github.com/repfigit/clearproof/issues/new?')).toBe(true);
    expect(params(url).get('template')).toBe('bug_report.yml');
    expect(params(url).get('title')).toBe('[Bug]: Proof rejected');
    expect(params(url).get('environment')).toBe(env);
  });

  it('adds the doctor summary and an empty title prefix when no title is given', async () => {
    const { issueUrl } = await import('../src/commands/report.js');
    const url = issueUrl('bug', undefined, { status: 'rejected' });
    expect(params(url).get('title')).toBe('[Bug]: ');
    expect(params(url).get('environment')).toContain('clearproof doctor:\n{\n  "status": "rejected"\n}');
  });

  it('builds a feature request link without environment details', async () => {
    const { issueUrl } = await import('../src/commands/report.js');
    const url = issueUrl('feature', undefined);
    expect(params(url).get('template')).toBe('feature_request.yml');
    expect(params(url).get('title')).toBe('[Feature]: ');
    expect(params(url).has('environment')).toBe(false);
    expect(params(issueUrl('feature', 'Batch proofs')).get('title')).toBe('[Feature]: Batch proofs');
  });
});

describe('report command', () => {
  it('prints a reviewable link and the private security route by default', async () => {
    await run(['--title', 'CLI crash']);
    expect(printed()).toContain('Open this link to review and submit the issue:');
    expect(printed()).toContain('https://github.com/repfigit/clearproof/issues/new?template=bug_report.yml');
    expect(printed()).toContain('https://github.com/repfigit/clearproof/security/advisories/new');
    expect(process.exitCode).toBe(0);
  });

  it('prints machine-readable JSON including a summarized doctor result', async () => {
    const file = doctorFile({ status: 'development_unapproved', proof_profile: 'pilot-transfer-v3', secret: 'SYNTHETIC-PRIVATE' });
    await run(['--json', '--doctor', file]);
    const result = JSON.parse(printed());
    expect(Object.keys(result)).toEqual(['url', 'environment', 'security']);
    expect(params(result.url).get('environment')).toContain('"proof_profile": "pilot-transfer-v3"');
    expect(result.url).not.toContain('SYNTHETIC-PRIVATE');
  });

  it('supports feature requests', async () => {
    await run(['--kind', 'feature', '--json']);
    expect(params(JSON.parse(printed()).url).get('template')).toBe('feature_request.yml');
  });

  it.each([
    [['--kind', 'question'], '--kind must be bug or feature'],
    [['--title', 'x'.repeat(201)], '--title must be one line'],
    [['--title', 'two\nlines'], '--title must be one line'],
    [['--kind', 'feature', '--doctor', 'x.json'], '--doctor applies to bug reports only'],
  ])('rejects invalid options %j', async (args, message) => {
    await run(args as string[]);
    expect(output).not.toHaveBeenCalled();
    expect(errors.mock.calls.join('')).toContain(message);
    expect(process.exitCode).toBe(1);
  });

  it('rejects unreadable or invalid doctor files without printing a link', async () => {
    await run(['--doctor', join(dir, 'missing.json')]);
    expect(process.exitCode).toBe(1);
    process.exitCode = 0;
    vi.resetModules();
    await run(['--doctor', doctorFile('not json')]);
    expect(output).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
});
