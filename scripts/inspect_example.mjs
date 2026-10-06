// SPDX-License-Identifier: Apache-2.0
// Source-checkout example: no proving keys, network, database or private input.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { verifyProof } from '@clearproof/proof';

try {
  if (process.argv.length !== 2) throw new Error('This example accepts no arguments');
  const fixture = new URL('../tests/vectors/compliance/', import.meta.url);
  const vkey = new URL('verification_key.json', fixture);
  const keyBytes = await readFile(vkey);
  // Existing public development fixture, never a production key or pilot v3 key.
  const keyDigest = createHash('sha256').update(keyBytes).digest('hex');
  if (keyDigest !== 'ea86c1d6cc973745d4ff691f277abb0f39ba8ed34e69ac3331189179f736c7d6') {
    throw new Error('Unexpected example verification key');
  }
  const proof = JSON.parse(await readFile(new URL('proof.json', fixture), 'utf8'));
  const signals = JSON.parse(await readFile(new URL('public.json', fixture), 'utf8'));
  const baseline = await verifyProof(proof, signals, fileURLToPath(vkey));
  if (!baseline.proofValid || baseline.valid || baseline.rejectionReasons.length !== 1 ||
      baseline.rejectionReasons[0] !== 'threshold_mismatch') {
    throw new Error('Unexpected historical fixture result');
  }
  const altered = [...signals];
  // Mutate the legacy public registry domain, keeping the original proof.
  altered[14] = String(BigInt(altered[14]) + 1n);
  const tampered = await verifyProof(proof, altered, fileURLToPath(vkey));
  if (tampered.proofValid) throw new Error('Tampered statement unexpectedly paired');
  console.log(JSON.stringify({
    schema_version: 'clearproof-example-inspection-v1',
    scope: 'historical-legacy-fixture',
    assurance: 'development-unapproved',
    public_signal_count: 16,
    verification_key_sha256: keyDigest,
    cryptographic_valid: baseline.proofValid,
    policy_accepted: baseline.valid,
    rejection_reasons: baseline.rejectionReasons,
    tampered_pairing_rejected: !tampered.proofValid,
    authorization_consumed: false,
    production_eligible: false,
  }, null, 2));
  // snarkjs may retain curve worker threads; this standalone example is done.
  process.exit(0);
} catch {
  console.error('Example inspection failed. Build @clearproof/proof and use the unchanged source fixture.');
  process.exit(1);
}
