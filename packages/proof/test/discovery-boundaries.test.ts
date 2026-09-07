import { beforeEach, expect, it, vi } from 'vitest';
import { lookup } from 'node:dns/promises';
import { EgressPolicy, resolveAddresses } from '../src/discovery-transport.js';
import { clearDiscoveryCache } from '../src/discovery.js';

vi.mock('node:dns/promises', () => ({ lookup: vi.fn() }));
beforeEach(() => { vi.mocked(lookup).mockReset(); });

it('retains every DNS answer for subsequent egress validation', async () => {
  vi.mocked(lookup).mockResolvedValue([
    { address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 },
  ] as never);
  expect(await resolveAddresses('operator.example', 443)).toEqual(['8.8.8.8', '127.0.0.1']);
  expect(lookup).toHaveBeenCalledWith('operator.example', { all: true });
  clearDiscoveryCache();
});

it('rejects malformed operator CIDRs and noncanonical authorities', () => {
  for (const cidr of ['127.0.0.1', '127.0.0.1/33', '::1/129', '127.0.0.1/08', 'bad/8', '127.0.0.1/8/extra']) {
    expect(() => new EgressPolicy({ 'operator.example': [cidr] })).toThrow('valid operator CIDRs');
  }
  for (const policy of [{ 'operator.example': [] }, { 'OPERATOR.example': ['127.0.0.1/8'] },
    { 'operator.example': '127.0.0.1/8' }]) {
    expect(() => new EgressPolicy(policy as Record<string, string[]>)).toThrow();
  }
});
