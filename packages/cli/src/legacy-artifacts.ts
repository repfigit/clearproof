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

/**
 * Default location for the legacy demo's development artifacts: the repository's artifacts/ directory.
 * No npm package supplies them. The artifacts in @clearproof/circuits 0.3.0 were compiled before the
 * sanctions-leaf hashing fix and no longer match the demo input, and later versions are source-only.
 * Generate matching artifacts with scripts/test_development_circuits.py and pass --artifacts.
 */
export function defaultArtifactsDir(local = path.resolve(__dirname, '../../../artifacts')): string {
  return local;
}

export function requireArtifactPaths(directory: string) {
  if (!artifactsAvailable(directory)) {
    throw new Error('Legacy circuit artifacts are missing or incomplete. Generate isolated development artifacts with '
      + 'scripts/test_development_circuits.py, then pass --artifacts <output>/legacy. '
      + 'See docs/internal/PILOT_DEVELOPMENT_ARTIFACTS.md.');
  }
  return resolveArtifactPaths(directory);
}
