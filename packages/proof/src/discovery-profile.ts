/** Domain-declared metadata. This profile does not establish VASP registration. */
import { createHash, createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto';

export const SPEC_VERSION = '0.4.0';
export const HPKE_SUITE = 'DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM';
export const KEY_PURPOSE = 'pii-envelope-v2';
export const MAX_DOCUMENT_BYTES = 65536;
export type DiscoveryFailure = 'invalid' | 'unsupported' | 'unavailable';
export class DiscoveryError extends Error {
  constructor(public readonly code: DiscoveryFailure, message: string) {
    super(message);
    this.name = 'DiscoveryError';
  }
}
export interface DiscoveryTarget { did: string; authority: string; host: string; port: number; url: string }
export interface ClearproofDiscoveryInfo {
  version: string;
  vasp: { did: string; name?: string; jurisdiction?: string };
  clearproof: {
    endpoint: string;
    /** Legacy field is informational only; never used as an HPKE key. */
    publicKey?: string;
    hpkePublicKey: string;
    hpkeKeyId: string;
    hpkeKeyPurpose: 'pii-envelope-v2';
    hpkeSuites: string[];
    supportedChains: number[];
    supportedVersions: string[];
    proofFormat: 'groth16';
  };
  contact?: { compliance?: string; technical?: string };
  updatedAt?: string;
}
const invalid = (message: string): never => { throw new DiscoveryError('invalid', message); };
export function parseTarget(value: string): DiscoveryTarget {
  if (typeof value !== 'string' || value.length > 512) return invalid('Expected a canonical domain or did:web identifier');
  const isDid = value.startsWith('did:web:');
  const parts = isDid ? value.slice(8).split(':') : [value];
  const authority = isDid ? parts[0].replaceAll('%3A', ':') : parts[0];
  const match = /^([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?$/.exec(authority);
  if (!match || match[0] !== authority) return invalid('Expected a lowercase ASCII DNS name and optional canonical port');
  const [, host, portString] = match;
  const labels = host.split('.');
  if (host.length > 253 || labels.length < 2 || !/[a-z]/.test(labels.at(-1)!) ||
      labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return invalid('IP literals, single-label hosts and ambiguous DNS names are unsupported');
  }
  const port = portString ? Number(portString) : 443;
  if (port > 65535 || (portString && port === 443)) return invalid('Invalid or noncanonical discovery port');
  if (parts.slice(1).some(part => !/^[A-Za-z0-9._-]+$/.test(part) || /[\r\n]/.test(part) || part === '.' || part === '..')) {
    return invalid('Unsupported did:web path component');
  }
  // The validated authority and path components are already canonical.
  const did = isDid ? value : 'did:web:' + authority.replaceAll(':', '%3A');
  return { did, authority, host, port, url: `https://${authority}/.well-known/clearproof.json` };
}
export function decodeHpkeKey(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}=?$/.test(value) || /[\r\n]/.test(value)) {
    return invalid('HPKE public key must be canonical base64url for 32 bytes');
  }
  const key = Buffer.from(value, 'base64url');
  if (key.toString('base64url') !== value.replace(/=$/, '')) return invalid('HPKE public key has noncanonical encoding');
  const integer = BigInt('0x' + Buffer.from(key).reverse().toString('hex'));
  if (integer >= (1n << 255n) - 19n) return invalid('HPKE public key is not a canonical X25519 point');
  try {
    const privateKey = createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.alloc(32, 42)]),
      format: 'der', type: 'pkcs8',
    });
    const publicKey = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), key]), format: 'der', type: 'spki',
    });
    const shared = diffieHellman({ privateKey, publicKey });
    if (shared.every(byte => byte === 0)) return invalid('HPKE public key is a low-order X25519 point');
  } catch { return invalid('HPKE public key is a low-order X25519 point'); }
  return key;
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.length <= 16 &&
    value.every(v => typeof v === 'string' && v.length > 0 && v.length <= 128) && new Set(value).size === value.length;
}
export function validateDocument(document: unknown, target: DiscoveryTarget): ClearproofDiscoveryInfo {
  if (!object(document) || typeof document.version !== 'string') return invalid('Discovery version is required');
  if (document.version !== SPEC_VERSION) throw new DiscoveryError('unsupported', 'Unsupported discovery version; migrate to 0.4.0');
  if (!object(document.vasp) || document.vasp.did !== target.did) return invalid('Discovery DID does not match the complete requested identity');
  const cp = document.clearproof;
  if (!object(cp)) return invalid('Missing clearproof capabilities');
  if (typeof cp.endpoint !== 'string' || cp.endpoint.length > 2048 ||
      !/^https:\/\/[A-Za-z0-9.:/_~%-]+$/.test(cp.endpoint) || /[\r\n]/.test(cp.endpoint)) {
    return invalid('Proof endpoint must be an HTTPS URL without credentials, query or fragment');
  }
  // Check raw authority; URL() canonicalization must not turn an alias into a match.
  const authority = cp.endpoint.slice(8).split('/')[0];
  if (authority !== target.authority || !cp.endpoint.slice(8 + authority.length).startsWith('/')) {
    return invalid('Proof endpoint must use the requested discovery authority');
  }
  const chains = cp.supportedChains;
  if (!Array.isArray(chains) || chains.length < 1 || chains.length > 64 ||
      chains.some(c => !Number.isSafeInteger(c) || c <= 0) || new Set(chains).size !== chains.length) {
    return invalid('supportedChains must be unique positive safe integers');
  }
  if (!stringArray(cp.supportedVersions) || !stringArray(cp.hpkeSuites)) return invalid('Versions and suites must be bounded nonempty string arrays');
  if (!cp.supportedVersions.includes(SPEC_VERSION) || cp.proofFormat !== 'groth16' || !cp.hpkeSuites.includes(HPKE_SUITE)) {
    throw new DiscoveryError('unsupported', 'No supported protocol, proof format or HPKE suite');
  }
  if (cp.hpkeKeyPurpose !== KEY_PURPOSE) return invalid('HPKE key purpose must be pii-envelope-v2');
  const key = decodeHpkeKey(cp.hpkePublicKey);
  const kid = createHash('sha256').update(key).digest().subarray(0, 16).toString('base64url');
  if (cp.hpkeKeyId !== kid && cp.hpkeKeyId !== kid + '==') return invalid('HPKE key ID does not match the advertised key');
  return structuredClone(document) as unknown as ClearproofDiscoveryInfo;
}
