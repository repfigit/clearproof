import { execFile } from 'node:child_process';
import { Command } from 'commander';

const rejected = (reason: string) => ({ status: 'rejected', reason, production_eligible: false });

/** Reconstruct the public diagnostic; never forward runtime stderr or arbitrary fields. */
export function doctorReport(stdout: string, code: number): Record<string, unknown> {
  const value = JSON.parse(stdout);
  if (!value || typeof value !== 'object' || value.production_eligible !== false) throw new Error('Invalid diagnostic');
  if (code === 1 && value.status === 'rejected' && typeof value.reason === 'string' &&
      /^[a-z][a-z0-9_]{0,63}$/.test(value.reason) && !/[^a-z0-9_]/.test(value.reason)) return rejected(value.reason);
  if (code !== 0 || value.status !== 'development_unapproved' ||
      typeof value.manifest_digest !== 'string' || value.manifest_digest.length !== 64 || !/^[a-f0-9]{64}$/.test(value.manifest_digest) ||
      !['pilot-transfer-v1', 'pilot-transfer-v2'].includes(value.proof_profile) ||
      typeof value.policy_schema_supported !== 'boolean' || typeof value.current_profile_supported !== 'boolean' ||
      JSON.stringify(value.checked_artifacts) !== JSON.stringify(['wasm', 'r1cs', 'proving_key', 'verification_key'])) {
    throw new Error('Invalid diagnostic');
  }
  return { status: value.status, manifest_digest: value.manifest_digest, proof_profile: value.proof_profile,
    checked_artifacts: value.checked_artifacts, production_eligible: false,
    policy_schema_supported: value.policy_schema_supported, current_profile_supported: value.current_profile_supported };
}

export const doctorCommand = new Command('doctor')
  .description('Inspect pinned local artifacts without downloading, proving or authorizing')
  .requiredOption('--python <executable>', 'Python environment with Clearproof installed')
  .requiredOption('--artifacts <directory>', 'Local artifact directory')
  .requiredOption('--trusted-manifest-digest <digest>', 'Independently selected manifest SHA-256 digest')
  .option('--mode <mode>', 'development or production (unapproved artifacts reject)', 'development')
  .action(async (options: { python: string; artifacts: string; trustedManifestDigest: string; mode: string }) => {
    let result: Record<string, unknown>;
    let code = 1;
    try {
      if (options.trustedManifestDigest.length !== 64 || !/^[a-f0-9]{64}$/.test(options.trustedManifestDigest) || !['development', 'production'].includes(options.mode)) {
        throw new Error('Invalid configuration');
      }
      const runtime = await new Promise<{ stdout: string; code: number }>((resolve, reject) => {
        execFile(options.python, ['-m', 'src.prover.pilot_artifacts', options.artifacts,
          '--trusted-manifest-digest', options.trustedManifestDigest, '--mode', options.mode],
        { timeout: 120_000, maxBuffer: 65536, encoding: 'utf8', shell: false }, (error, stdout) => {
          if (error && error.code !== 1) reject(error);
          else resolve({ stdout, code: error ? 1 : 0 });
        });
      });
      result = doctorReport(runtime.stdout, runtime.code);
      code = runtime.code;
    } catch {
      result = rejected('doctor_configuration_or_runtime_failed');
    }
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = code;
  });
