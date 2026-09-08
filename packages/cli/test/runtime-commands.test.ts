import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';

const spawn = vi.hoisted(() => vi.fn());
vi.mock('node:child_process', () => ({ spawn }));
let output: ReturnType<typeof vi.spyOn>;
const originalExitCode = process.exitCode;
beforeEach(() => {
  vi.resetModules();
  spawn.mockReset();
  output = vi.spyOn(console, 'log').mockImplementation(() => {});
  process.exitCode = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = originalExitCode;
});
function child(code: number | null, failure = false) {
  spawn.mockImplementation(() => {
    const child = new EventEmitter();
    queueMicrotask(() => {
      if (failure) child.emit('error', new Error('SYNTHETIC-PRIVATE-ERROR'));
      child.emit('close', code);
    });
    return child;
  });
}
for (const name of ['history', 'counterparty'] as const) {
  const run = async (optional = false) => {
    if (name === 'history') {
      const { verifyHistoryCommand } = await import('../src/commands/verify-history.js');
      await verifyHistoryCommand.parseAsync(['--python', '/python;literal', '--bundle', '/bundle',
        '--trust', '/trust', '--artifacts', '/artifacts', '--runtime', '/runtime', '--node', '/node',
        ...(optional ? ['--verified-at', '123'] : [])], { from: 'user' });
    } else {
      const { counterpartyCommand } = await import('../src/commands/counterparty.js');
      await counterpartyCommand.parseAsync(['--python', '/python;literal', '--request', '/request',
        '--trust', '/trust', '--observed-at', '123',
        ...(optional ? ['--deadline', '456', '--behavior', 'timeout'] : [])], { from: 'user' });
    }
  };
  describe(`${name} runtime adapter`, () => {
    it.each([0, 1, 2, 3, null])('maps child exit %s to the documented CLI status', async code => {
      child(code);
      await run();
      expect(process.exitCode).toBe(name === 'history' && code === 1 ? 1 : code === 0 ? 0 : 2);
      expect(spawn.mock.calls[0][0]).toBe('/python;literal');
      expect(spawn.mock.calls[0][2]).toEqual({ stdio: 'inherit', shell: false });
      expect(output).not.toHaveBeenCalled();
    });
    it('forwards the independently selected paths and optional evaluation clock', async () => {
      child(0);
      await run(true);
      expect(spawn.mock.calls[0][1]).toEqual(name === 'history' ? [
        '-m', 'src.prover.history_cli', '--bundle', '/bundle', '--trust', '/trust',
        '--artifacts', '/artifacts', '--runtime', '/runtime', '--node', '/node', '--verified-at', '123',
      ] : ['-m', 'src.protocol.bridges.pilot_bilateral_cli', '--request', '/request', '--trust', '/trust',
        '--observed-at', '123', '--behavior', 'timeout', '--deadline', '456']);
    });
    it('reports runtime unavailability without exposing process errors', async () => {
      child(-2, true);
      await run();
      expect(process.exitCode).toBe(2);
      expect(output).toHaveBeenCalledOnce();
      const report = JSON.parse(output.mock.calls[0][0] as string);
      expect(report.outcome).toBe(name === 'history' ? 'indeterminate' : 'invalid-input');
      expect(JSON.stringify(report)).not.toContain('SYNTHETIC-PRIVATE');
    });
  });
}
