import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const circuits = require('../index.js');

describe('@clearproof/circuits metadata', () => {
  it('matches the compliance circuit public signal layout', () => {
    expect(circuits.PUBLIC_SIGNAL_COUNT).toBe(16);
    expect(circuits.signals.CREDENTIAL_NULLIFIER).toBe(14);
    expect(circuits.signals.PROOF_EXPIRES_AT).toBe(15);
    expect(Object.values(circuits.signals)).toEqual([...Array(16).keys()]);
  });
});
