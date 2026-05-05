import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { defaultArtifactsDir, resolveArtifactPaths } from '../src/commands/demo.js';

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-cli-test-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('demo artifact resolution', () => {
  it('defaults to bundled @clearproof/circuits artifacts', () => {
    const artifactsDir = defaultArtifactsDir();

    expect(fs.existsSync(path.join(artifactsDir, 'compliance.wasm'))).toBe(true);
    expect(fs.existsSync(path.join(artifactsDir, 'compliance_final.zkey'))).toBe(true);
    expect(fs.existsSync(path.join(artifactsDir, 'verification_key.json'))).toBe(true);
  });

  it('uses packaged wasm when artifacts are from @clearproof/circuits', () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, 'compliance.wasm'), '');

    expect(resolveArtifactPaths(dir).wasmPath).toBe(path.join(dir, 'compliance.wasm'));
  });

  it('falls back to compiled repo wasm layout', () => {
    const dir = makeTempDir();
    fs.mkdirSync(path.join(dir, 'compliance_js'));
    fs.writeFileSync(path.join(dir, 'compliance_js', 'compliance.wasm'), '');

    expect(resolveArtifactPaths(dir).wasmPath).toBe(
      path.join(dir, 'compliance_js', 'compliance.wasm'),
    );
  });
});
