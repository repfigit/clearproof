import fs from 'node:fs';
import path from 'node:path';

export function resolveArtifactPaths(directory: string) {
  const dir = path.resolve(directory);
  const packaged = path.join(dir, 'compliance.wasm');
  return {
    wasmPath: fs.existsSync(packaged) ? packaged : path.join(dir, 'compliance_js', 'compliance.wasm'),
    zkeyPath: path.join(dir, 'compliance_final.zkey'),
    vkeyPath: path.join(dir, 'verification_key.json'),
  };
}

export function artifactsAvailable(directory: string): boolean {
  return Object.values(resolveArtifactPaths(directory)).every(file => {
    try {
      const info = fs.lstatSync(file);
      return info.isFile() && info.size > 0;
    } catch { return false; }
  });
}

export function defaultArtifactsDir(
  packaged?: string,
  local = path.resolve(__dirname, '../../../artifacts'),
): string {
  if (packaged === undefined) {
    try {
      packaged = (require('@clearproof/circuits') as { artifacts?: { dir?: string } }).artifacts?.dir;
    } catch { /* Source checkout may not have workspace packages installed. */ }
  }
  return packaged && artifactsAvailable(packaged) ? packaged : local;
}

export function requireArtifactPaths(directory: string) {
  if (!artifactsAvailable(directory)) {
    throw new Error('Legacy circuit artifacts are missing or incomplete. Generate isolated development artifacts with '
      + 'scripts/test_development_circuits.py, then pass --artifacts <output>/legacy. '
      + 'See docs/internal/PILOT_DEVELOPMENT_ARTIFACTS.md.');
  }
  return resolveArtifactPaths(directory);
}
