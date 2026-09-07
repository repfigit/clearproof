import { afterEach, expect, it, vi } from 'vitest';

const originalArgv = process.argv;
afterEach(() => {
  process.argv = originalArgv;
  vi.restoreAllMocks();
});

it('registers the supported command set and dispatches real documentation help', async () => {
  vi.resetModules();
  const { Command } = await import('commander');
  const parse = vi.spyOn(Command.prototype, 'parseAsync');
  const output = vi.spyOn(console, 'log').mockImplementation(() => {});
  process.argv = [process.execPath, 'clearproof', 'help', 'api'];
  await import('../src/index.js');
  expect(parse).toHaveBeenCalledOnce();
  await parse.mock.results[0].value;
  const program = parse.mock.contexts[0];
  expect(program.commands.map(command => command.name()).sort()).toEqual([
    'authorize-current', 'counterparty', 'demo', 'doctor', 'explain', 'help',
    'inspect-current', 'investigation', 'observation', 'policy', 'prove', 'recipes',
    'verify', 'verify-history',
  ]);
  expect(output.mock.calls.flat().join('\n')).toContain('/wallet/ownership/verify');
});
