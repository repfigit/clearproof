import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalBytes, recordDigest } from '../src/canonical.js';
const vectors = JSON.parse(readFileSync(join(__dirname, '../../../specs/fixtures/transfer-v1.json'), 'utf8'));
describe('canonical private transfer and minimized evidence commitments', () => {
  it.each(vectors.records)('matches Python $domain bytes and digest', (vector: any) => {
    expect(canonicalBytes(vector.value).toString()).toBe(vector.canonical);
    expect(recordDigest(vector.domain, vector.value)).toBe(vector.digest);
    const reversed = Object.fromEntries(Object.entries(vector.value).reverse());
    expect(recordDigest(vector.domain, reversed)).toBe(vector.digest);
  });
  it('sorts numeric-looking keys lexically and separates domains', () => {
    expect(canonicalBytes({ '2':'b', '10':'a', a:'quote"/\\' }).toString()).toBe('{"10":"a","2":"b","a":"quote\\"/\\\\"}');
    expect(recordDigest('clearproof/transfer/v1', {})).not.toBe(recordDigest('clearproof/evidence-receipt/v1', {}));
  });
  it.each([NaN, Infinity, 1.5, 2**53, '\n', 'é', {'':1}, {x:undefined}, Array(257).fill('x'), new Date(), Array(3)])
  ('rejects values outside the profile', value => { expect(() => canonicalBytes(value)).toThrow(); });
  it('rejects accessors without executing them', () => {
    let called = false;
    const object = { get field() { called = true; return 'value'; } };
    expect(() => canonicalBytes(object)).toThrow();
    expect(called).toBe(false);
  });
  it('bounds work before allocating oversized serialization', () => {
    expect(() => canonicalBytes(Array(256).fill('x'.repeat(4096)))).toThrow();
    let nested: unknown = null;
    for (let i = 0; i < 10; i++) nested = [nested];
    expect(() => canonicalBytes(nested)).toThrow();
  });
});

it('bounds encoded bytes after JSON escaping expands valid ASCII strings', () => {
  expect(() => canonicalBytes(Array(16).fill('"'.repeat(4000)))).toThrow('exceeds 64 KiB');
});

it('rejects invalid domains and object keys before creating a commitment', () => {
  for (const domain of ['other/transfer/v1', 'clearproof/transfer/v0', 'clearproof/transfer/v1\n']) {
    expect(() => recordDigest(domain, {})).toThrow('Invalid commitment domain');
  }
  for (const key of ['', '\n', 'key\n', 'key\r', 'key\r\n', 'x'.repeat(129)]) {
    expect(() => canonicalBytes({ [key]: 1 })).toThrow('Invalid canonical record key');
  }
});
