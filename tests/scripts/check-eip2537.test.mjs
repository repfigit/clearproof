import { afterEach, beforeEach, expect, test, vi } from 'vitest';

const pairingTrue = '0x' + '00'.repeat(31) + '01';
class Exit extends Error {
  constructor(code) { super('captured script exit'); this.code = code; }
}

let output;
beforeEach(() => {
  vi.resetModules();
  vi.useFakeTimers();
  output = vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(process, 'exit').mockImplementation(code => { throw new Exit(code); });
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function execute(fetcher, code) {
  vi.stubGlobal('fetch', fetcher);
  await expect(import('../../scripts/check_eip2537.mjs')).rejects.toMatchObject({ code });
  expect(vi.getTimerCount()).toBe(0);
  return output.mock.calls.map(args => args.join(' '));
}

test('confirms only an exact successful pairing result with a valid infinity pair', async () => {
  const fetcher = vi.fn(async (_url, options) => {
    const request = JSON.parse(options.body);
    expect(request.method).toBe('eth_call');
    expect(request.params[0].to).toBe('0x000000000000000000000000000000000000000f');
    expect(request.params[0].data).toBe('0x' + '00'.repeat(384));
    return { ok: true, json: async () => ({ result: pairingTrue }) };
  });
  const lines = await execute(fetcher, 0);
  expect(lines.filter(line => line.includes('PRESENT'))).toHaveLength(10);
  expect(lines.at(-1)).toContain('All chains have EIP-2537.');
});

test.each([
  { error: { code: -32005, message: 'rate limited' } },
  { result: '0x' },
  { result: '0x1234' },
])('does not report success for an unconfirmed RPC result %j', async response => {
  const lines = await execute(vi.fn(async () => ({ ok: true, json: async () => response })), 1);
  expect(lines.at(-1)).toContain('10 chain(s) without confirmed EIP-2537.');
  expect(lines.some(line => line.includes('PRESENT'))).toBe(false);
});

test('failed fetches exhaust fallbacks and release their abort timers', async () => {
  const fetcher = vi.fn(async () => { throw new Error('synthetic connection failure'); });
  const lines = await execute(fetcher, 1);
  expect(fetcher).toHaveBeenCalledTimes(13);
  expect(lines.filter(line => line.includes('RPC-ERROR'))).toHaveLength(10);
});

test('HTTP errors cannot masquerade as successful pairing responses', async () => {
  const lines = await execute(vi.fn(async () => ({ ok: false, status: 503, json: async () => ({ result: pairingTrue }) })), 1);
  expect(lines.at(-1)).toContain('10 chain(s) without confirmed EIP-2537.');
});

test('aborts stalled requests and exhausts fallback URLs without leaving timers', async () => {
  const fetcher = vi.fn((_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('synthetic abort')), { once: true });
  }));
  const execution = execute(fetcher, 1);
  await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  await vi.runAllTimersAsync();
  const lines = await execution;
  expect(fetcher).toHaveBeenCalledTimes(13);
  expect(lines.at(-1)).toContain('10 chain(s) without confirmed EIP-2537.');
});

test('recovers on a fallback endpoint after the primary fails', async () => {
  const fetcher = vi.fn(async () => ({ ok: true, json: async () => ({ result: pairingTrue }) }));
  fetcher.mockRejectedValueOnce(new Error('synthetic primary unavailable'));
  const lines = await execute(fetcher, 0);
  expect(fetcher).toHaveBeenCalledTimes(11);
  expect(lines.filter(line => line.includes('PRESENT'))).toHaveLength(10);
});
