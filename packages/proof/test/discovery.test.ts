import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { DiscoveryClient, DiscoveryError, EgressPolicy, discoverVASP, supportsChain } from '../src/discovery.js';
import { decodeHpkeKey, parseTarget, validateDocument } from '../src/discovery-profile.js';
import * as exports from '../src/index.js';

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, '../../../specs/fixtures', name), 'utf8'));
const document = fixture('discovery-0.4.0.json');
const invalidVectors = fixture('discovery-invalid.json') as { path: string; value: unknown; error: string }[];
const networkVectors = fixture('discovery-network.json') as { address: string; allowed: boolean }[];

describe('shared Python publishing and Node consuming profile', () => {
  it('consumes Python HPKE metadata without a legacy publicKey', () => {
    expect(validateDocument(document, parseTarget('beneficiary.example'))).toEqual(document);
    expect(exports.DiscoveryClient).toBe(DiscoveryClient);
    expect('discoverAllVASPs' in exports).toBe(false);
  });
  it.each(invalidVectors)('rejects $path = $value', ({ path, value, error }) => {
    const data = structuredClone(document), parts = path.split('.');
    let parent = data;
    for (const part of parts.slice(0, -1)) parent = parent[part];
    parent[parts.at(-1)!] = value;
    expect(() => validateDocument(data, parseTarget('beneficiary.example'))).toThrow(expect.objectContaining({ code: error }));
  });
  it.each(networkVectors)('applies shared egress policy to $address', ({ address, allowed }) => {
    expect(new EgressPolicy().permits('beneficiary.example', address)).toBe(allowed);
  });
  it('preserves the complete DID including port and path', () => {
    const target = parseTarget('did:web:beneficiary.example%3A8443:vasps:eu');
    expect(target.url).toBe('https://beneficiary.example:8443/.well-known/clearproof.json');
    expect(() => validateDocument(document, target)).toThrow(/identity/);
    const data = structuredClone(document);
    data.vasp.did = target.did;
    data.clearproof.endpoint = 'https://beneficiary.example:8443/clearproof/v1';
    expect(validateDocument(data, target)).toEqual(data);
  });
  it.each(['127.0.0.1', '169.254.169.254', '2130706433', '0x7f000001', '[::1]', 'localhost',
    'https://x.example/', 'x.example/other', 'x.example@evil.example', 'x.example?query', 'x.example#fragment',
    'X.example', 'x.example.', 'x.example:443', 'x.example:0', 'x.example:65536', 'x.example\n',
    'did:web:x.example:..', 'did:web:x.example%3a8443', 'did:web:x.example:alice\n', 'did:web:x.example:a%2fb'])
  ('rejects ambiguous target %s', identity => { expect(() => parseTarget(identity)).toThrow(DiscoveryError); });
  it('rejects bad options and copies exact operator exceptions', () => {
    for (const options of [{ timeoutMs: 0 }, { cacheTtlMs: NaN }, { cacheTtlMs: -1 }, { timeoutMs: 60001 }]) {
      expect(() => new DiscoveryClient(options)).toThrow(DiscoveryError);
    }
    const config = { 'beneficiary.example:8443': ['10.0.0.0/8'] };
    const policy = new EgressPolicy(config);
    config['beneficiary.example:8443'].push('127.0.0.0/8');
    expect(policy.permits('beneficiary.example:8443', '10.1.2.3')).toBe(true);
    expect(policy.permits('beneficiary.example', '10.1.2.3')).toBe(false);
    expect(policy.permits('beneficiary.example:8443', '127.0.0.1')).toBe(false);
  });
  it('accepts canonical padding variants', () => {
    expect(decodeHpkeKey(document.clearproof.hpkePublicKey.replace(/=$/, ''))).toEqual(decodeHpkeKey(document.clearproof.hpkePublicKey));
  });
  it.each([0n, 1n, (1n << 255n) - 20n, (1n << 255n) - 19n, (1n << 255n) - 18n, (1n << 255n) + 9n])
  ('rejects low-order and noncanonical X25519 point %s', integer => {
    const bytes = Buffer.from(integer.toString(16).padStart(64, '0'), 'hex').reverse();
    expect(() => decodeHpkeKey(bytes.toString('base64url'))).toThrow(DiscoveryError);
  });
  it('uses integral JSON number semantics for chain IDs', () => {
    const data = structuredClone(document);
    data.clearproof.supportedChains = [1.0];
    expect(validateDocument(data, parseTarget('beneficiary.example'))).toEqual(data);
  });
});

describe('real TLS, DNS pinning and caches', () => {
  let directory: string, server: Server, ca: string, authority: string;
  let requests: { host?: string; sni: string; path?: string }[];
  let status: number, body: Buffer | undefined, encoding: string | undefined, contentType: string, delay: number;
  let doc: typeof document;
  const resolver = vi.fn(async () => ['127.0.0.1']);
  const options = () => ({ resolver, ca, privateDestinations: { [authority]: ['127.0.0.1/32'] }, cacheTtlMs: 0 });
  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'clearproof-discovery-'));
    const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
      '-days', '1', '-subj', '/CN=beneficiary.example', '-addext', 'subjectAltName=DNS:beneficiary.example'], { stdio: 'ignore' });
    ca = readFileSync(cert, 'utf8');
    server = createServer({ key: readFileSync(key), cert: ca }, (request, response) => {
      requests.push({ host: request.headers.host, sni: (request.socket as TLSSocket).servername, path: request.url });
      const send = () => {
        if (response.destroyed) return;
        response.writeHead(status, { 'Content-Type': contentType, ...(encoding === undefined ? {} : { 'Content-Encoding': encoding }),
          Location: 'https://169.254.169.254/credentials' });
        response.end(body ?? JSON.stringify(doc));
      };
      if (delay) {
        const timer = setTimeout(send, delay);
        response.on('close', () => clearTimeout(timer));
      } else send();
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    authority = `beneficiary.example:${(server.address() as AddressInfo).port}`;
  });
  beforeEach(() => {
    status = 200; body = undefined; encoding = 'identity'; contentType = 'application/json'; delay = 0; requests = [];
    doc = structuredClone(document);
    doc.vasp.did = parseTarget(authority).did;
    doc.clearproof.endpoint = `https://${authority}/clearproof/v1`;
    resolver.mockReset().mockResolvedValue(['127.0.0.1']);
  });
  afterEach(() => { server.closeAllConnections(); vi.unstubAllEnvs(); });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    rmSync(directory, { recursive: true, force: true });
  });
  it('pins the IP while retaining TLS identity and Host; ignores proxies', async () => {
    vi.stubEnv('HTTPS_PROXY', 'http://127.0.0.1:1');
    expect(await discoverVASP(authority, options())).toEqual(doc);
    expect(requests).toEqual([{ host: authority, sni: 'beneficiary.example', path: '/.well-known/clearproof.json' }]);
    expect(resolver).toHaveBeenCalledTimes(1);
    expect(await supportsChain(authority, 11155111, options())).toBe(true);
  });
  it('accepts an uncompressed response without a Content-Encoding header', async () => {
    encoding = undefined;
    expect(await new DiscoveryClient(options()).discover(authority)).toEqual(doc);
    expect(requests).toHaveLength(1);
  });
  it('does not connect when DNS completes after the request deadline', async () => {
    let release!: (addresses: string[]) => void;
    const pending = new Promise<string[]>(resolve => { release = resolve; });
    const client = new DiscoveryClient({ ...options(), timeoutMs: 10, resolver: () => pending });
    await expect(client.discover(authority)).rejects.toMatchObject({ code: 'unavailable' });
    release(['127.0.0.1']);
    await new Promise<void>(resolve => setImmediate(resolve));
    expect(requests).toHaveLength(0);
    expect(await new DiscoveryClient(options()).discover(authority)).toEqual(doc);
    expect(requests).toHaveLength(1);
  });
  it('blocks rebinding after a successful fetch', async () => {
    const client = new DiscoveryClient(options());
    await client.discover(authority);
    resolver.mockResolvedValue(['169.254.169.254']);
    await expect(client.discover(authority)).rejects.toMatchObject({ code: 'invalid' });
    expect(requests).toHaveLength(1);
  });
  it('blocks private and mixed answers before connecting', async () => {
    await expect(new DiscoveryClient({ resolver, ca }).discover(authority)).rejects.toMatchObject({ code: 'invalid' });
    resolver.mockResolvedValue(['8.8.8.8', '127.0.0.1']);
    await expect(new DiscoveryClient({ resolver, ca }).discover(authority)).rejects.toMatchObject({ code: 'invalid' });
    expect(requests).toHaveLength(0);
  });
  it('requires a trusted certificate and matching hostname', async () => {
    await expect(new DiscoveryClient({ ...options(), ca: undefined }).discover(authority)).rejects.toMatchObject({ code: 'unavailable' });
    const wrong = authority.replace('beneficiary', 'wrong');
    await expect(new DiscoveryClient({ ...options(), privateDestinations: { [wrong]: ['127.0.0.1/32'] } }).discover(wrong))
      .rejects.toMatchObject({ code: 'unavailable' });
    expect(requests).toHaveLength(0);
  });
  it.each([[301, 'invalid'], [302, 'invalid'], [307, 'invalid'], [404, 'unsupported'], [503, 'unavailable']] as const)
  ('classifies HTTP %s without redirects', async (code, error) => {
    status = code;
    await expect(new DiscoveryClient(options()).discover(authority)).rejects.toMatchObject({ code: error });
    expect(resolver).toHaveBeenCalledTimes(1);
    expect(requests).toHaveLength(1);
  });
  it.each(['html', 'gzip', 'json', 'utf8', 'oversize'])('rejects invalid response %s', async kind => {
    if (kind === 'html') contentType = 'text/html';
    if (kind === 'gzip') encoding = 'gzip';
    if (kind === 'json') body = Buffer.from('{invalid');
    if (kind === 'utf8') body = Buffer.from([255]);
    if (kind === 'oversize') body = Buffer.alloc(65537, 32);
    await expect(new DiscoveryClient(options()).discover(authority)).rejects.toMatchObject({ code: 'invalid' });
  });
  it('bounds DNS and response-body waits', async () => {
    await expect(new DiscoveryClient({ ...options(), timeoutMs: 30, resolver: () => new Promise(() => {}) }).discover(authority))
      .rejects.toMatchObject({ code: 'unavailable' });
    delay = 10000;
    await expect(new DiscoveryClient({ ...options(), timeoutMs: 100 }).discover(authority)).rejects.toMatchObject({ code: 'unavailable' });
  });
  it('isolates cache trust and returned objects; never caches errors', async () => {
    const a = new DiscoveryClient({ ...options(), cacheTtlMs: 300000 });
    const b = new DiscoveryClient({ ...options(), cacheTtlMs: 300000 });
    (await a.discover(authority)).clearproof.hpkeKeyId = 'changed';
    expect(await a.discover(authority)).toEqual(doc);
    expect(requests).toHaveLength(1);
    await b.discover(authority);
    expect(requests).toHaveLength(2);
    a.clearCache(); status = 503;
    await expect(a.discover(authority)).rejects.toMatchObject({ code: 'unavailable' });
    status = 200; await a.discover(authority);
    expect(requests).toHaveLength(4);
  });
  it('fences in-flight writes on rotation; slow replies cannot extend TTL', async () => {
    let release!: (addresses: string[]) => void;
    const deferred = new Promise<string[]>(resolve => { release = resolve; });
    const client = new DiscoveryClient({ ...options(), resolver: () => deferred, cacheTtlMs: 300000 });
    const pending = client.discover(authority);
    client.clearCache(); release(['127.0.0.1']);
    await pending; await client.discover(authority);
    expect(requests).toHaveLength(2);
    delay = 40;
    const slow = new DiscoveryClient({ ...options(), cacheTtlMs: 1 });
    await slow.discover(authority); await slow.discover(authority);
    expect(requests).toHaveLength(4);
  });
});

it('preserves validated DID identity across canonical hosts, ports and paths', () => {
  for (const host of ['a.example', 'a-b.sub.example', 'xn--bcher-kva.example']) {
    for (const port of [undefined, 1, 65535]) {
      for (const path of ['', ':vasps:EU', ':a_b:c.d-e', ':8443']) {
        const authority = port === undefined ? host : `${host}:${port}`;
        const did = 'did:web:' + authority.replaceAll(':', '%3A') + path;
        const target = parseTarget(did);
        expect(target).toEqual({ did, authority, host, port: port ?? 443,
          url: `https://${authority}/.well-known/clearproof.json` });
        expect(parseTarget(target.did)).toEqual(target);
      }
    }
  }
});
