import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { defaultArtifactsDir, resolveArtifactPaths, requireArtifactPaths } from '../src/legacy-artifacts.js';

const temporary: string[] = [];
function directory(complete = false, compiled = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-cli-test-'));
  temporary.push(dir);
  if (complete) {
    const wasmDir = compiled ? path.join(dir, 'compliance_js') : dir;
    fs.mkdirSync(wasmDir, { recursive: true });
    fs.writeFileSync(path.join(wasmDir, 'compliance.wasm'), 'layout fixture only');
    for (const name of ['compliance_final.zkey', 'verification_key.json']) fs.writeFileSync(path.join(dir, name), 'fixture');
  }
  return dir;
}
afterEach(() => { for (const dir of temporary.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });

describe('legacy artifact selection', () => {
  it('defaults to the repository artifacts directory; no package supplies artifacts', () => {
    const local = directory(true, true);
    expect(defaultArtifactsDir(local)).toBe(local);
    expect(defaultArtifactsDir()).toBe(path.resolve(__dirname, '../../../artifacts'));
  });

  it('resolves packaged wasm and rejects incomplete, empty or symlinked artifacts before proving', () => {
    const dir = directory(true);
    expect(resolveArtifactPaths(dir).wasmPath).toBe(path.join(dir, 'compliance.wasm'));
    fs.writeFileSync(path.join(dir, 'compliance_final.zkey'), '');
    expect(() => requireArtifactPaths(dir)).toThrow('missing or incomplete');
    fs.unlinkSync(path.join(dir, 'compliance_final.zkey'));
    fs.symlinkSync(path.join(dir, 'verification_key.json'), path.join(dir, 'compliance_final.zkey'));
    expect(() => requireArtifactPaths(dir)).toThrow('missing or incomplete');
    expect(() => requireArtifactPaths(directory())).toThrow('--artifacts <output>/legacy');
  });

  it('applies the same symlink rule when selecting the wasm as when validating it', () => {
    const dir = directory(true, true);
    const compiled = path.join(dir, 'compliance_js', 'compliance.wasm');
    fs.symlinkSync(compiled, path.join(dir, 'compliance.wasm'));
    expect(resolveArtifactPaths(dir).wasmPath).toBe(compiled);
    expect(requireArtifactPaths(dir).wasmPath).toBe(compiled);
  });

  it('checks only the artifacts a command needs', () => {
    const dir = directory();
    fs.writeFileSync(path.join(dir, 'verification_key.json'), 'fixture');
    expect(requireArtifactPaths(dir, ['vkeyPath']).vkeyPath).toBe(path.join(dir, 'verification_key.json'));
    expect(() => requireArtifactPaths(dir)).toThrow('missing or incomplete');
  });
});
