import { describe, expect, it } from 'vitest';
import { PROJECT_STATUS } from '../src/index';
import { readFileSync } from 'node:fs';

describe('public project status', () => {
  it('publishes explicit assurance and software capacity separately from circuit capacity', () => {
    expect(Object.isFrozen(PROJECT_STATUS)).toBe(true);
    expect(PROJECT_STATUS.assurance).toContain('development-only');
    expect(PROJECT_STATUS.capacity).toContain('1,024 enrollments');
    expect(PROJECT_STATUS.proofProfile).toBe('pilot-transfer-v3');
    expect(PROJECT_STATUS.schemaVersion).toBe(1);
    expect(Number.isFinite(Date.parse(PROJECT_STATUS.checkedAt))).toBe(true);
  });

  it('separates the registry-verified release from the source checkout version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const release = JSON.parse(readFileSync(new URL('../../../docs/releases/2026-10-07-npm.json', import.meta.url), 'utf8'));
    expect(PROJECT_STATUS.npmVersion).toBe(release.npmVersion);
    expect(PROJECT_STATUS.checkedAt).toBe(release.checkedAt);
    expect(release.packages).toHaveLength(5);
    expect(release.packages.every((entry: { version: string }) => entry.version === release.npmVersion)).toBe(true);
    expect(PROJECT_STATUS.sourceVersion).toBe(pkg.version);
  });
});
