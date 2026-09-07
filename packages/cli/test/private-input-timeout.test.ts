import { afterEach, expect, it, vi } from 'vitest';
import { PassThrough } from 'node:stream';
import { readPrivateInput } from '../src/api-client.js';

afterEach(() => vi.useRealTimers());
it('destroys stalled private input and releases the timeout after rejection', async () => {
  vi.useFakeTimers();
  const stream = new PassThrough();
  const rejection = expect(readPrivateInput(stream)).rejects.toThrow('Input timeout');
  await vi.advanceTimersByTimeAsync(10000);
  await rejection;
  expect(stream.destroyed).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});
