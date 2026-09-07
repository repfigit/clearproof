/** Constrained Node.js discovery. TLS metadata is self-declared, not registry assurance. */
import { performance } from 'node:perf_hooks';
import { DiscoveryError, parseTarget, validateDocument, type ClearproofDiscoveryInfo } from './discovery-profile.js';
import { EgressPolicy, fetchDocument, resolveAddresses, type DiscoveryResolver } from './discovery-transport.js';

export { DiscoveryError, EgressPolicy };
export type { ClearproofDiscoveryInfo, DiscoveryResolver };
export interface DiscoveryOptions {
  /** 0 disables caching; maximum 1 hour. Default 5 minutes. */
  cacheTtlMs?: number;
  /** Whole-request deadline including DNS and response body, default 10 seconds. */
  timeoutMs?: number;
  /** Operator-only exact authority -> CIDRs. Never populate from transfer requests. */
  privateDestinations?: Readonly<Record<string, readonly string[]>>;
  /** Operator DNS dependency; every answer is still checked and pinned. */
  resolver?: DiscoveryResolver;
  /** Operator CA bundle; certificate and original-hostname checks stay enabled. */
  ca?: string;
}
export class DiscoveryClient {
  private readonly policy: EgressPolicy;
  private readonly resolver: DiscoveryResolver;
  private readonly ca?: string;
  private readonly ttl: number;
  private readonly timeout: number;
  private generation = 0;
  private readonly cache = new Map<string, { expires: number; data: ClearproofDiscoveryInfo }>();
  constructor(options: DiscoveryOptions = {}) {
    this.ttl = options.cacheTtlMs ?? 300_000;
    this.timeout = options.timeoutMs ?? 10_000;
    if (!Number.isFinite(this.ttl) || this.ttl < 0 || this.ttl > 3_600_000) throw new DiscoveryError('invalid', 'Cache TTL must be finite and between 0 and 3600000 ms');
    if (!Number.isFinite(this.timeout) || this.timeout <= 0 || this.timeout > 60_000) throw new DiscoveryError('invalid', 'Timeout must be finite and between 0 and 60000 ms');
    this.policy = new EgressPolicy(options.privateDestinations);
    this.resolver = options.resolver ?? resolveAddresses;
    this.ca = options.ca;
  }
  clearCache(): void { this.generation++; this.cache.clear(); }
  async discover(identity: string): Promise<ClearproofDiscoveryInfo> {
    const target = parseTarget(identity), now = performance.now(), generation = this.generation;
    const cached = this.cache.get(target.did);
    this.cache.delete(target.did);
    if (cached && cached.expires > now) { this.cache.set(target.did, cached); return structuredClone(cached.data); }
    const document = validateDocument(await fetchDocument(target, this.policy, this.resolver, this.timeout, this.ca), target);
    if (this.ttl && now + this.ttl > performance.now() && generation === this.generation) {
      this.cache.set(target.did, { expires: now + this.ttl, data: structuredClone(document) });
      while (this.cache.size > 128) this.cache.delete(this.cache.keys().next().value!);
    }
    return document;
  }
}
const defaultClient = new DiscoveryClient();
/** Unsupported, unavailable and invalid responses throw DiscoveryError with a distinct code. */
export async function discoverVASP(identity: string, options?: DiscoveryOptions): Promise<ClearproofDiscoveryInfo> {
  // Custom policy calls are isolated. Retain a DiscoveryClient for custom-policy caching.
  return (options ? new DiscoveryClient(options) : defaultClient).discover(identity);
}
export async function supportsChain(identity: string, chainId: number, options?: DiscoveryOptions): Promise<boolean> {
  return (await discoverVASP(identity, options)).clearproof.supportedChains.includes(chainId);
}
export function clearDiscoveryCache(): void { defaultClient.clearCache(); }
