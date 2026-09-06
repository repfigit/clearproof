import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const circuits = require('../index.js');

describe('@clearproof/circuits metadata', () => {
  it('matches the compliance circuit public signal layout', () => {
    expect(circuits.PUBLIC_SIGNAL_COUNT).toBe(16);
    expect(circuits.signals.CREDENTIAL_NULLIFIER).toBe(14);
    expect(circuits.signals.PROOF_EXPIRES_AT).toBe(15);
    expect(Object.values(circuits.signals)).toEqual([...Array(16).keys()]);
  });
});

describe('source package artifact availability', () => {
  it('distinguishes absent, complete and partial local artifact sets', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const os = require('node:os');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-package-'));
    try {
      fs.copyFileSync(require.resolve('../index.js'), path.join(dir, 'index.js'));
      const isolated = require(path.join(dir, 'index.js'));
      const names = ['compliance.wasm', 'compliance_final.zkey', 'verification_key.json'];
      expect(isolated.artifactStatus()).toEqual({ available: false, missing: names, profile: 'legacy-compliance-16' });
      fs.mkdirSync(path.join(dir, 'artifacts'));
      for (const name of names) fs.writeFileSync(path.join(dir, 'artifacts', name), 'availability fixture only');
      expect(isolated.artifactStatus().available).toBe(true);
      fs.unlinkSync(path.join(dir, 'artifacts/compliance_final.zkey'));
      expect(isolated.artifactStatus()).toEqual({ available: false,
        missing: ['compliance_final.zkey'], profile: 'legacy-compliance-16' });
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
