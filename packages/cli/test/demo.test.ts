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
  it('prefers a complete packaged set and falls back when package contents are absent', () => {
    const packaged = directory(true), local = directory(true, true);
    expect(defaultArtifactsDir(packaged, local)).toBe(packaged);
    fs.unlinkSync(path.join(packaged, 'compliance_final.zkey'));
    expect(defaultArtifactsDir(packaged, local)).toBe(local);
    expect(requireArtifactPaths(local).wasmPath).toBe(path.join(local, 'compliance_js', 'compliance.wasm'));
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
});
