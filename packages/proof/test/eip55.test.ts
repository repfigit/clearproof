import { describe, expect, it } from 'vitest';
import { toChecksumAddress } from '../src/eip55.js';
import { isoEpoch } from '../src/wallet-ownership.js';

describe('toChecksumAddress', () => {
  it('checksums a valid lowercase address', () => {
    expect(toChecksumAddress('0x' + 'a'.repeat(40))).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it('rejects malformed addresses', () => {
    expect(() => toChecksumAddress('0x1234')).toThrow('Invalid Ethereum address');
  });
});

describe('isoEpoch', () => {
  it('rejects invalid timestamps', () => {
    expect(() => isoEpoch(-1)).toThrow('Invalid SIWE timestamp');
  });
});
