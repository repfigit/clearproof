/** Restricted canonical encoding for pilot records; no policy or authorization decision. */
import { createHash } from 'node:crypto';
export function canonicalBytes(value: unknown): Buffer {
  let budget = 65536;
  const charge = (n: number) => { budget -= n; if (budget < 0) throw new Error('Canonical record exceeds validation budget'); };
  const encode = (item: unknown, depth: number): string => {
    charge(8);
    if (depth > 8) throw new Error('Canonical record exceeds nesting limit');
    if (item === null || typeof item === 'boolean') return JSON.stringify(item);
    if (typeof item === 'number' && Number.isSafeInteger(item) && !Object.is(item, -0)) return String(item);
    if (typeof item === 'string' && item.length <= 4096 && /^[ -~]*$/.test(item) && !/[\r\n]/.test(item)) {
      charge(item.length); return JSON.stringify(item);
    }
    if (Array.isArray(item) && item.length <= 256) {
      // Reject sparse arrays; JSON.stringify would silently turn holes into null.
      const parts: string[] = [];
      for (let i = 0; i < item.length; i++) {
        if (!Object.hasOwn(item, i)) throw new Error('Sparse canonical array');
        parts.push(encode(item[i], depth + 1));
      }
      return '[' + parts.join(',') + ']';
    }
    if (item && typeof item === 'object' && Object.getPrototypeOf(item) === Object.prototype) {
      if (Object.values(Object.getOwnPropertyDescriptors(item)).some(d => d.get || d.set)) throw new Error('Canonical accessors are forbidden');
      const entries = Object.entries(item);
      if (entries.length > 64 || Reflect.ownKeys(item).length !== entries.length) throw new Error('Invalid canonical object');
      return '{' + entries.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, child]) => {
        if (!/^[ -~]{1,128}$/.test(key) || /[\r\n]/.test(key)) throw new Error('Invalid canonical record key');
        charge(key.length + 3);
        return JSON.stringify(key) + ':' + encode(child, depth + 1);
      }).join(',') + '}';
    }
    throw new Error('Unsupported canonical record value');
  };
  const bytes = Buffer.from(encode(value, 0), 'ascii');
  if (bytes.length > 65536) throw new Error('Canonical record exceeds 64 KiB');
  return bytes;
}
export function recordDigest(domain: string, value: unknown): string {
  if (!/^clearproof\/[a-z-]+\/v[1-9][0-9]*$/.test(domain) || /[\r\n]/.test(domain)) throw new Error('Invalid commitment domain');
  return createHash('sha256').update(domain, 'ascii').update(Buffer.from([0])).update(canonicalBytes(value)).digest('hex');
}
