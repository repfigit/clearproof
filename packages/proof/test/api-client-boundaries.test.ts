import { afterEach, expect, it, vi } from 'vitest';
import { requestReport } from '../src/api-client.js';

afterEach(() => { vi.unstubAllGlobals(); });

it('combines caller cancellation with its deadline and rejects absent response bodies', async () => {
  const controller = new AbortController();
  controller.abort();
  const fetch = vi.fn().mockResolvedValue({ ok: true, body: null });
  vi.stubGlobal('fetch', fetch);
  await expect(requestReport('https://operator.example', 'token', '/pilot/proof/inspect', Buffer.from('{}'), controller.signal))
    .rejects.toThrow('Comparison request rejected');
  const options = fetch.mock.calls[0][1];
  expect(options.signal.aborted).toBe(true);
  expect(options.redirect).toBe('error');
});

it('releases the stream lock even when cancellation itself fails', async () => {
  const reader = {
    read: vi.fn().mockResolvedValue({ done: true }),
    cancel: vi.fn().mockRejectedValue(new Error('stream cancellation failed')),
    releaseLock: vi.fn(),
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, body: { getReader: () => reader } }));
  await expect(requestReport('https://operator.example', 'token', '/pilot/proof/inspect', Buffer.from('{}')))
    .rejects.toThrow('stream cancellation failed');
  expect(reader.releaseLock).toHaveBeenCalledOnce();
});

it('cancels an oversized streamed response before parsing it', async () => {
  const reader = {
    read: vi.fn().mockResolvedValue({ done: false, value: new Uint8Array(2 * 1024 * 1024 + 1) }),
    cancel: vi.fn().mockResolvedValue(undefined),
    releaseLock: vi.fn(),
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, body: { getReader: () => reader } }));
  await expect(requestReport('https://operator.example', 'token', '/pilot/proof/inspect', Buffer.from('{}')))
    .rejects.toThrow('Response limit exceeded');
  expect(reader.read).toHaveBeenCalledOnce();
  expect(reader.cancel).toHaveBeenCalledOnce();
  expect(reader.releaseLock).toHaveBeenCalledOnce();
});
