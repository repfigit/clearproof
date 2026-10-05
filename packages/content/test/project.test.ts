import { describe, expect, it } from 'vitest';
import { PROJECT_STATUS } from '../src/index';
import { readFileSync } from 'node:fs';

describe('public project status', () => {
  it('publishes explicit assurance and software capacity separately from circuit capacity', () => {
    expect(Object.isFrozen(PROJECT_STATUS)).toBe(true);
    expect(PROJECT_STATUS.assurance).toContain('development-only');
    expect(PROJECT_STATUS.capacity).toContain('256 enrollments');
    expect(PROJECT_STATUS.proofProfile).toBe('pilot-transfer-v3');
    expect(PROJECT_STATUS.schemaVersion).toBe(1);
    expect(Number.isFinite(Date.parse(PROJECT_STATUS.checkedAt))).toBe(true);
  });

  it('uses the verified release version of the published content package', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    expect(PROJECT_STATUS.npmVersion).toBe(pkg.version);
  });
});
