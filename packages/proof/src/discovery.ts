/**
 * VASP discovery module.
 *
 * Discovers clearproof-compatible VASPs via two mechanisms:
 * 1. Well-known URL: https://<domain>/.well-known/clearproof.json
 * 2. On-chain VASPRegistry (if provider is configured)
 *
 * Usage:
 *   import { discoverVASP, discoverAllVASPs } from '@clearproof/proof';
 *
 *   // Discover a specific counterparty by domain
 *   const info = await discoverVASP('exchange.example');
 *
 *   // Discover all registered VASPs from on-chain registry
 *   const all = await discoverAllVASPs({ registryAddress, provider });
 */

export interface ClearproofDiscoveryInfo {
  version: string;
  vasp?: {
    name?: string;
    did?: string;
    jurisdiction?: string;
  };
  clearproof: {
    endpoint: string;
    publicKey: string;
    supportedChains: number[];
    supportedVersions?: string[];
    proofFormat?: string;
  };
  contact?: {
    compliance?: string;
    technical?: string;
  };
  updatedAt?: string;
}

export interface DiscoveryOptions {
  /** Cache TTL in milliseconds (default: 3600000 = 1 hour) */
  cacheTtlMs?: number;
  /** Request timeout in milliseconds (default: 10000) */
  timeoutMs?: number;
}

// Simple in-memory cache
const cache = new Map<string, { data: ClearproofDiscoveryInfo; expiresAt: number }>();

/**
 * Discover a clearproof-compatible VASP by domain.
 *
 * Fetches https://<domain>/.well-known/clearproof.json and validates
 * the response against the expected schema.
 *
 * Returns null if the domain does not support clearproof (404 or invalid).
 */
export async function discoverVASP(
  domain: string,
  options: DiscoveryOptions = {},
): Promise<ClearproofDiscoveryInfo | null> {
  const ttl = options.cacheTtlMs ?? 3_600_000;
  const timeout = options.timeoutMs ?? 10_000;

  // Check cache
  const cached = cache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  const url = `https://${domain}/.well-known/clearproof.json`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);

    if (!resp.ok) {
      return null;
    }

    const data = (await resp.json()) as ClearproofDiscoveryInfo;

    // Validate required fields
    if (!data.clearproof?.endpoint || !data.clearproof?.publicKey || !data.clearproof?.supportedChains) {
      return null;
    }

    // Cache
    cache.set(domain, { data, expiresAt: Date.now() + ttl });

    return data;
  } catch {
    return null;
  }
}

/**
 * Check if a domain supports clearproof on a specific chain.
 */
export async function supportsChain(
  domain: string,
  chainId: number,
  options: DiscoveryOptions = {},
): Promise<boolean> {
  const info = await discoverVASP(domain, options);
  if (!info) return false;
  return info.clearproof.supportedChains.includes(chainId);
}

/**
 * Clear the discovery cache (useful for testing or forced refresh).
 */
export function clearDiscoveryCache(): void {
  cache.clear();
}
