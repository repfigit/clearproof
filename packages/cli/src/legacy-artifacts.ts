import fs from 'node:fs';
import path from 'node:path';

export type LegacyArtifactPaths = { wasmPath: string; zkeyPath: string; vkeyPath: string };
export type LegacyArtifact = keyof LegacyArtifactPaths;
const ALL_ARTIFACTS: readonly LegacyArtifact[] = ['wasmPath', 'zkeyPath', 'vkeyPath'];

/** Regular, non-empty file; symlinks are rejected so selection and validation agree. */
function isArtifactFile(file: string): boolean {
  try {
    const info = fs.lstatSync(file);
    return info.isFile() && info.size > 0;
  } catch { return false; }
}

export function resolveArtifactPaths(directory: string): LegacyArtifactPaths {
  const dir = path.resolve(directory);
  const packaged = path.join(dir, 'compliance.wasm');
  return {
    wasmPath: isArtifactFile(packaged) ? packaged : path.join(dir, 'compliance_js', 'compliance.wasm'),
    zkeyPath: path.join(dir, 'compliance_final.zkey'),
    vkeyPath: path.join(dir, 'verification_key.json'),
  };
}

export function artifactsAvailable(directory: string, required: readonly LegacyArtifact[] = ALL_ARTIFACTS): boolean {
  const paths = resolveArtifactPaths(directory);
  return required.every(key => isArtifactFile(paths[key]));
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

/** Resolve artifact paths, throwing an actionable error unless every `required` artifact is present. */
export function requireArtifactPaths(directory: string, required: readonly LegacyArtifact[] = ALL_ARTIFACTS) {
  if (!artifactsAvailable(directory, required)) {
    throw new Error('Legacy circuit artifacts are missing or incomplete. Generate isolated development artifacts with '
      + 'scripts/test_development_circuits.py, then pass --artifacts <output>/legacy. '
      + 'See docs/internal/PILOT_DEVELOPMENT_ARTIFACTS.md.');
  }
  return resolveArtifactPaths(directory);
}
