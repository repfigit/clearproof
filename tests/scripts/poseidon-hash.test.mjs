import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { afterEach, expect, test, vi } from 'vitest';

const require = createRequire(import.meta.url);
const script = require.resolve('../../scripts/poseidon_hash.js');
afterEach(() => { vi.restoreAllMocks(); delete require.cache[script]; });

async function execute(chunks) {
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  const stdout = [];
  const stderr = [];
  vi.spyOn(process, 'stdin', 'get').mockReturnValue(Readable.from(chunks));
  vi.spyOn(process.stdout, 'write').mockImplementation(chunk => {
    stdout.push(String(chunk)); finish(0); return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(chunk => { stderr.push(String(chunk)); return true; });
  vi.spyOn(process, 'exit').mockImplementation(code => { finish(code); });
  delete require.cache[script];
  require(script);
  const code = await done;
  return { code, stdout: stdout.join(''), stderr: stderr.join('') };
}

test.each([
  ['[1,', '2]'],
  [' \n{"inputs":', '["1","2"]}', '\n'],
])('hashes streamed array or wrapped decimal inputs: %j', async (...chunks) => {
  const result = await execute(chunks.map(value => Buffer.from(value)));
  // Published circomlib Poseidon([1, 2]) reference value.
  expect(result).toEqual({ code: 0, stderr: '',
    stdout: '7853200120776062878684798364095072458815029376092732009249414926327459813530\n' });
});

test.each(['', '{', 'null', '{}', '{"inputs":1}'])('rejects malformed input %j before hashing', async input => {
  const result = await execute([Buffer.from(input)]);
  expect(result.code).toBe(1);
  expect(result.stdout).toBe('');
  expect(result.stderr).toMatch(/^Invalid input JSON: .+\n$/);
  expect(process.exit).toHaveBeenCalledTimes(1);
});

test.each(['["not-an-integer"]', '[1.5]', '[]', JSON.stringify(Array(17).fill('1'))])(
  'reports hashing or integer conversion failures for %s', async input => {
    const result = await execute([Buffer.from(input)]);
    expect(result.code).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toMatch(/^Error: .+\n$/);
    expect(process.exit).toHaveBeenCalledTimes(1);
  },
);
