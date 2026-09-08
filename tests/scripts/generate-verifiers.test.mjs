import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const root = resolve(import.meta.dirname, '../..');
const cases = [
  {
    name: 'BN254', key: 'tests/vectors/compliance/verification_key.json',
    script: 'scripts/generate_verifier.mjs',
    contract: 'packages/contracts/contracts/Groth16Verifier.sol',
    load: () => import('../../scripts/generate_verifier.mjs'),
  },
  {
    name: 'BLS12-381', key: 'tests/vectors/compliance-bls/verification_key_bls.json',
    script: 'scripts/generate_verifier_bls.mjs',
    contract: 'packages/contracts/contracts/bench/Groth16VerifierBLS.sol',
    load: () => import('../../scripts/generate_verifier_bls.mjs'),
  },
];
class Exit extends Error {
  constructor(code) { super('captured generator exit'); this.code = code; }
}
let directory, originalArgs, keyPath, outputPath;
beforeEach(() => {
  vi.resetModules();
  directory = mkdtempSync(join(tmpdir(), 'cp-verifier-test-'));
  keyPath = join(directory, 'key.json');
  outputPath = join(directory, 'Verifier.sol');
  originalArgs = process.argv;
  process.argv = ['node', 'generator', keyPath, outputPath];
  vi.spyOn(process, 'exit').mockImplementation(code => { throw new Exit(code); });
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  process.argv = originalArgs;
  vi.restoreAllMocks();
  rmSync(directory, { recursive: true, force: true });
});

for (const generator of cases) {
  test(`${generator.name} reproduces the committed verifier from its vector key`, async () => {
    writeFileSync(keyPath, readFileSync(join(root, generator.key)));
    await generator.load();
    expect(readFileSync(outputPath, 'utf8')).toBe(readFileSync(join(root, generator.contract), 'utf8'));
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('16 public signals, 17 IC points'));
  });

  test(`${generator.name} CLI works from a foreign working directory`, () => {
    const output = execFileSync(process.execPath, [
      join(root, generator.script), join(root, generator.key), outputPath,
    ], { cwd: directory, encoding: 'utf8', timeout: 15_000 });
    expect(output).toContain('16 public signals, 17 IC points');
    expect(readFileSync(outputPath, 'utf8')).toBe(readFileSync(join(root, generator.contract), 'utf8'));
  });

  test.each([{ args: [] }, { args: ['key-only'] }])(`${generator.name} rejects missing arguments $args`, async ({ args }) => {
    process.argv = ['node', 'generator', ...args];
    await expect(generator.load()).rejects.toMatchObject({ code: 1 });
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('usage:'));
    expect(existsSync(outputPath)).toBe(false);
  });

  test.each(['protocol', 'curve'])(`${generator.name} rejects an unsupported %s`, async field => {
    const key = JSON.parse(readFileSync(join(root, generator.key), 'utf8'));
    key[field] = 'unsupported';
    writeFileSync(keyPath, JSON.stringify(key));
    await expect(generator.load()).rejects.toMatchObject({ code: 1 });
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('unsupported key:'));
    expect(existsSync(outputPath)).toBe(false);
  });

  test(`${generator.name} rejects inconsistent public-input metadata before writing`, async () => {
    const key = JSON.parse(readFileSync(join(root, generator.key), 'utf8'));
    key.nPublic += 1;
    writeFileSync(keyPath, JSON.stringify(key));
    await expect(generator.load()).rejects.toMatchObject({ code: 1 });
    expect(existsSync(outputPath)).toBe(false);
  });

  test(`${generator.name} leaves existing output intact on malformed JSON`, async () => {
    writeFileSync(keyPath, '{invalid');
    writeFileSync(outputPath, 'preserve existing output');
    await expect(generator.load()).rejects.toBeInstanceOf(SyntaxError);
    expect(readFileSync(outputPath, 'utf8')).toBe('preserve existing output');
  });
}
