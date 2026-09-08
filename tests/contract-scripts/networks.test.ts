import { afterEach, expect, test, vi } from 'vitest';
import { NETWORKS, getConfiguredNetworks, getRpcUrl } from '../../packages/contracts/scripts/networks';

afterEach(() => vi.unstubAllEnvs());

test('unfiltered and empty selections retain every configured network', () => {
  expect(getConfiguredNetworks()).toEqual(Object.values(NETWORKS));
  expect(getConfiguredNetworks([])).toEqual(Object.values(NETWORKS));
});

test('selection ignores unknown and duplicate names and preserves configuration order', () => {
  expect(getConfiguredNetworks(['base', 'sepolia', 'base', 'unknown'])).toEqual([NETWORKS.sepolia, NETWORKS.base]);
  expect(getConfiguredNetworks(['unknown'])).toEqual([]);
});

test('RPC overrides apply to only the selected network and empty values use defaults', () => {
  vi.stubEnv('BASE_RPC_URL', 'http://127.0.0.1:8545');
  vi.stubEnv('SEPOLIA_RPC_URL', '');
  expect(getRpcUrl(NETWORKS.base)).toBe('http://127.0.0.1:8545');
  expect(getRpcUrl(NETWORKS.sepolia)).toBe(NETWORKS.sepolia.defaultRpc);
  vi.stubEnv('BASE_RPC_URL', undefined);
  expect(getRpcUrl(NETWORKS.base)).toBe(NETWORKS.base.defaultRpc);
});
