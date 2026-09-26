import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const circuits = require('../index.js');
const repoCircuits = join(dirname(require.resolve('../index.js')), '..', '..', 'circuits');
const sha256 = (data) => createHash('sha256').update(data).digest('hex');

describe('@clearproof/circuits source package', () => {
  it('describes the current pilot profile consistently with the circuit source', () => {
    expect(circuits.pilot.profile).toBe('pilot-transfer-v3');
    const main = readFileSync(circuits.pilot.main, 'utf8');
    expect(main).toContain(`= ${circuits.pilot.template};`);
    const declared = main.match(/component main \{public \[([^\]]+)\]\}/)[1].split(',').map((s) => s.trim());
    expect(declared).toEqual(circuits.pilot.publicSignals);
    expect(circuits.pilot.template).toBe(
      `PilotCompliance(${circuits.pilot.treeDepths.issuance}, ${circuits.pilot.treeDepths.authorizedIssuers}, ${circuits.pilot.treeDepths.sanctions})`,
    );
  });

  it('keeps the legacy profile separate with its 16-signal layout', () => {
    expect(circuits.legacy.publicSignals).toHaveLength(16);
    expect(readFileSync(circuits.legacy.main, 'utf8')).toContain(`= ${circuits.legacy.template};`);
  });

  it('matches the repository sources except for rewritten circomlib includes', () => {
    const manifest = JSON.parse(readFileSync(join(circuits.dir, 'MANIFEST.json'), 'utf8'));
    for (const [rel, hashes] of Object.entries(manifest.files)) {
      const original = readFileSync(join(repoCircuits, rel), 'utf8');
      const packaged = readFileSync(join(circuits.dir, rel), 'utf8');
      expect(sha256(original)).toBe(hashes.repository_sha256);
      expect(sha256(packaged)).toBe(hashes.package_sha256);
      expect(packaged).toBe(original.replace(/include "(?:\.\.\/)+node_modules\/circomlib\//g, 'include "circomlib/'));
    }
    expect(Object.keys(manifest.files)).toContain('pilot_compliance.circom');
  });

  it('only includes packaged files or circomlib, and every include resolves', () => {
    const files = readdirSync(circuits.dir, { recursive: true }).filter((f) => f.endsWith('.circom'));
    const circomlib = dirname(require.resolve('circomlib/package.json'));
    for (const file of files) {
      const text = readFileSync(join(circuits.dir, file), 'utf8');
      for (const [, target] of text.matchAll(/include "([^"]+)"/g)) {
        const resolved = target.startsWith('circomlib/')
          ? join(circomlib, target.slice('circomlib/'.length))
          : join(circuits.dir, dirname(file), target);
        expect(existsSync(resolved), `${file} -> ${target}`).toBe(true);
      }
    }
  });

  it('ships no compiled artifacts or keys', () => {
    const files = readdirSync(circuits.dir, { recursive: true });
    expect(files.filter((f) => /\.(wasm|zkey|r1cs|ptau)$|verification_key/i.test(f))).toEqual([]);
  });

  it('packs only sources, manifest, entry points and README', () => {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
      cwd: dirname(require.resolve('../index.js')), encoding: 'utf8',
    });
    // npm 11 returns an array; npm 12 inside a workspace returns an object keyed by package name.
    const data = JSON.parse(out);
    const entry = Array.isArray(data) ? data[0] : Object.values(data)[0];
    const paths = entry.files.map((f) => f.path).sort();
    expect(paths.every((p) => /^(circuits\/.*\.circom|circuits\/MANIFEST\.json|index\.js|index\.d\.ts|README\.md|package\.json)$/.test(p))).toBe(true);
    expect(paths).toContain('circuits/pilot_compliance.circom');
  });
});
