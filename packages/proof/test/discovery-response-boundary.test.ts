import { EventEmitter } from 'node:events';
import { expect, it, vi } from 'vitest';
import { parseTarget } from '../src/discovery-profile.js';
import { EgressPolicy, fetchDocument } from '../src/discovery-transport.js';

const request = vi.hoisted(() => vi.fn());
vi.mock('node:https', () => ({ request }));

it('rejects a response missing HTTP status and closes the request', async () => {
  const destroyed = vi.fn();
  let status: number | undefined;
  request.mockImplementation((_options, callback) => {
    const req = Object.assign(new EventEmitter(), {
      destroy: destroyed,
      end: () => {
        const response = Object.assign(new EventEmitter(), {
          statusCode: status, headers: { 'content-type': 'application/json' },
        });
        callback(response);
        response.emit('data', Buffer.from('{"synthetic":true}'));
        response.emit('end');
      },
    });
    return req;
  });
  const target = parseTarget('operator.example');
  const resolver = async () => ['8.8.8.8'];
  await expect(fetchDocument(target, new EgressPolicy(), resolver, 1000))
    .rejects.toMatchObject({ code: 'unavailable', message: 'Discovery service returned HTTP 0' });
  expect(destroyed).toHaveBeenCalledTimes(1);
  status = 200;
  await expect(fetchDocument(target, new EgressPolicy(), resolver, 1000)).resolves.toEqual({ synthetic: true });
  expect(destroyed).toHaveBeenCalledTimes(2);
  expect(request).toHaveBeenCalledTimes(2);
});
