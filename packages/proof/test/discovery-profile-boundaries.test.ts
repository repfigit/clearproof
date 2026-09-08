import { expect, it, vi } from 'vitest';
import { diffieHellman } from 'node:crypto';
import { decodeHpkeKey, parseTarget, validateDocument } from '../src/discovery-profile.js';

vi.mock('node:crypto', async importOriginal => ({
  ...await importOriginal<typeof import('node:crypto')>(), diffieHellman: vi.fn(),
}));

it('rejects malformed capability objects and versions', () => {
  const target = parseTarget('operator.example');
  for (const document of [null, [], {}, { version: 1 }, { version: '0.4.0', vasp: { did: target.did }, clearproof: null }]) {
    expect(() => validateDocument(document, target)).toThrow();
  }
});

it('rejects noncanonical key padding bits before key agreement', () => {
  const key = Buffer.alloc(32); key[0] = 9;
  const encoded = key.toString('base64url');
  expect(() => decodeHpkeKey(encoded.slice(0, -1) + 'B')).toThrow('noncanonical encoding');
  expect(diffieHellman).not.toHaveBeenCalled();
});

it('rejects an all-zero shared secret even if the crypto provider returns it', () => {
  vi.mocked(diffieHellman).mockReturnValue(Buffer.alloc(32));
  const key = Buffer.alloc(32); key[0] = 9;
  expect(() => decodeHpkeKey(key.toString('base64url'))).toThrow('low-order');
  expect(diffieHellman).toHaveBeenCalledOnce();
});
