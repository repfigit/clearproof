import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  clearDiscoveryCache,
  discoverVASP,
  supportsChain,
} from '../src/discovery.js';
import * as proofExports from '../src/index.js';

afterEach(() => {
  clearDiscoveryCache();
  vi.restoreAllMocks();
});

describe('VASP discovery', () => {
  it('exports only implemented well-known discovery helpers', () => {
    expect(proofExports.discoverVASP).toBe(discoverVASP);
    expect('discoverAllVASPs' in proofExports).toBe(false);
  });

  it('returns null for invalid well-known responses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ version: '1.0' }),
      }),
    );

    await expect(discoverVASP('exchange.example')).resolves.toBeNull();
  });

  it('discovers and caches valid well-known responses', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        version: '1.0',
        clearproof: {
          endpoint: 'https://exchange.example/clearproof',
          publicKey: 'age1counterparty',
          supportedChains: [1, 11155111],
        },
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(supportsChain('exchange.example', 11155111)).resolves.toBe(true);
    await expect(supportsChain('exchange.example', 8453)).resolves.toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
