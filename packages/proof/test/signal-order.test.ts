import { expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AUTHORIZATION_NULLIFIER_INDEX,
  PILOT_PUBLIC_SIGNAL_COUNT,
  PROOF_EXPIRES_AT_INDEX,
} from '../src/authorization.js';

/**
 * Cross-language guard for the pilot-transfer-v3 signal order (CLAUDE.md invariant 1).
 * authorization.ts reads the nullifier and expiry by index; the Python prover owns the order.
 */
const PYTHON_PROVER = join('src', 'prover', 'pilot_compliance.py');

function findRepoFile(relative: string): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(dir, relative);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) throw new Error(`${relative} not found above ${fileURLToPath(import.meta.url)}`);
    dir = parent;
  }
}

function pythonPublicSignals(): string[] {
  const source = readFileSync(findRepoFile(PYTHON_PROVER), 'utf8');
  const match = /^PUBLIC_SIGNALS\s*=\s*[([]([\s\S]*?)[)\]]/m.exec(source);
  if (!match) throw new Error('PUBLIC_SIGNALS tuple not found in pilot_compliance.py');
  return [...match[1].matchAll(/["']([a-z_]+)["']/g)].map(m => m[1]);
}

it('keeps authorization.ts signal indices aligned with the Python pilot prover', () => {
  const signals = pythonPublicSignals();
  expect(signals).toHaveLength(PILOT_PUBLIC_SIGNAL_COUNT);
  expect(PILOT_PUBLIC_SIGNAL_COUNT).toBe(8);
  expect(signals[AUTHORIZATION_NULLIFIER_INDEX]).toBe('authorization_nullifier');
  expect(signals[PROOF_EXPIRES_AT_INDEX]).toBe('proof_expires_at');
  expect(AUTHORIZATION_NULLIFIER_INDEX).toBe(3);
  expect(PROOF_EXPIRES_AT_INDEX).toBe(5);
});
