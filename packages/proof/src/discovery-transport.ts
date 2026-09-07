/** Node-only HTTPS transport. DNS is resolved once; sockets use the vetted IP. */
import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import type { ClientRequest } from 'node:http';
import { BlockList, isIP } from 'node:net';
import { DiscoveryError, MAX_DOCUMENT_BYTES, parseTarget, type DiscoveryTarget } from './discovery-profile.js';

export type DiscoveryResolver = (host: string, port: number) => Promise<readonly string[]>;
export const resolveAddresses: DiscoveryResolver = async host => (await lookup(host, { all: true })).map(a => a.address);
const v4Deny = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'];
const v6Deny = ['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20'];
function blockList(cidrs: readonly string[]): BlockList {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const [address, prefix, extra] = cidr.split('/');
    const family = isIP(address);
    if (extra !== undefined || !family || !/^(0|[1-9][0-9]*)$/.test(prefix ?? '') || Number(prefix) > (family === 4 ? 32 : 128)) {
      throw new DiscoveryError('invalid', 'Expected valid operator CIDRs');
    }
    list.addSubnet(address, Number(prefix), family === 4 ? 'ipv4' : 'ipv6');
  }
  return list;
}
const denied4 = blockList(v4Deny), denied6 = blockList(v6Deny), public6 = blockList(['2000::/3']);
export class EgressPolicy {
  private readonly exceptions = new Map<string, BlockList>();
  constructor(privateDestinations: Readonly<Record<string, readonly string[]>> = {}) {
    for (const [authority, cidrs] of Object.entries(privateDestinations)) {
      if (parseTarget(authority).authority !== authority || !Array.isArray(cidrs) || !cidrs.length) {
        throw new DiscoveryError('invalid', 'Private destinations require exact authorities and nonempty CIDR lists');
      }
      this.exceptions.set(authority, blockList(cidrs));
    }
  }
  permits(authority: string, address: string): boolean {
    if (address.includes('%')) return false;
    const family = isIP(address);
    if (!family) return false;
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (this.exceptions.get(authority)?.check(address, type)) return true;
    return family === 4 ? !denied4.check(address, type) : public6.check(address, type) && !denied6.check(address, type);
  }
}
export function fetchDocument(
  target: DiscoveryTarget, policy: EgressPolicy, resolver: DiscoveryResolver, timeoutMs: number, ca?: string,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let req: ClientRequest | undefined;
    const finish = (error?: unknown, data?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req?.destroy();
      if (error) reject(error instanceof DiscoveryError ? error : new DiscoveryError('unavailable', 'Discovery DNS, TLS or connection failure'));
      else resolve(data);
    };
    const timer = setTimeout(() => finish(new DiscoveryError('unavailable', 'Discovery request timed out')), timeoutMs);
    void (async () => {
      const addresses = await resolver(target.host, target.port);
      if (settled) return;
      if (!addresses.length || addresses.some(ip => !policy.permits(target.authority, ip))) {
        throw new DiscoveryError('invalid', 'Discovery DNS answer contains a disallowed address');
      }
      // The IP cannot be rebound by a second DNS response. Original identity
      // remains in TLS SNI, certificate verification and HTTP Host.
      req = request({
        hostname: addresses[0], port: target.port, servername: target.host,
        path: '/.well-known/clearproof.json', method: 'GET', agent: false,
        rejectUnauthorized: true, minVersion: 'TLSv1.2', ca,
        headers: { Host: target.authority, Accept: 'application/json', 'Accept-Encoding': 'identity' },
      }, response => {
        const status = response.statusCode ?? 0;
        if (status === 404) return finish(new DiscoveryError('unsupported', 'Discovery document returned HTTP 404'));
        if (status >= 300 && status < 400) return finish(new DiscoveryError('invalid', 'Discovery redirects are forbidden'));
        if (status !== 200) return finish(new DiscoveryError('unavailable', `Discovery service returned HTTP ${status}`));
        if (response.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') {
          return finish(new DiscoveryError('invalid', 'Discovery requires application/json'));
        }
        if ((response.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          return finish(new DiscoveryError('invalid', 'Compressed discovery responses are unsupported'));
        }
        let size = 0;
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_DOCUMENT_BYTES) return finish(new DiscoveryError('invalid', 'Discovery document exceeds 64 KiB'));
          chunks.push(chunk);
        });
        response.on('error', finish);
        response.on('end', () => {
          if (settled) return;
          try { finish(undefined, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
          catch { finish(new DiscoveryError('invalid', 'Discovery response is not valid UTF-8 JSON')); }
        });
      });
      req.on('error', finish);
      req.end();
    })().catch(finish);
  });
}
