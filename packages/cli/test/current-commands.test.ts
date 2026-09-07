import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const clients = vi.hoisted(() => ({
  authorizeCurrentProof: vi.fn(), inspectCurrentProof: vi.fn(),
  createObservation: vi.fn(), readObservation: vi.fn(),
  reportObservationCohort: vi.fn(), listObservations: vi.fn(),
}));
const readInput = vi.hoisted(() => vi.fn());
vi.mock('@clearproof/proof', async importOriginal => ({
  ...await importOriginal<typeof import('@clearproof/proof')>(), ...clients,
}));
vi.mock('../src/api-client.js', async importOriginal => ({
  ...await importOriginal<typeof import('../src/api-client.js')>(),
  readPrivateInput: readInput,
}));

const cases = [
  { name: 'authorize-current', client: 'authorizeCurrentProof', module: 'authorize-current', symbol: 'authorizeCurrentCommand', args: [] },
  { name: 'inspect-current', client: 'inspectCurrentProof', module: 'inspect-current', symbol: 'inspectCurrentCommand', args: [] },
  { name: 'observation create', client: 'createObservation', module: 'observation', symbol: 'observationCommand', args: ['create'] },
  { name: 'observation read', client: 'readObservation', module: 'observation', symbol: 'observationCommand', args: ['read'] },
  { name: 'observation report', client: 'reportObservationCohort', module: 'observation', symbol: 'observationCommand', args: ['report'] },
  { name: 'observation list', client: 'listObservations', module: 'observation', symbol: 'observationCommand', args: ['list'] },
] as const;
const bytes = Buffer.from('{"synthetic":"request"}');
let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
const originalExitCode = process.exitCode;

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  vi.stubEnv('CLEARPROOF_API_TOKEN', 'synthetic-token');
  process.exitCode = 0;
  output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  errors = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  readInput.mockReset().mockResolvedValue(bytes);
  for (const client of Object.values(clients)) client.mockReset().mockResolvedValue({ cryptographic_valid: true });
});
afterEach(() => {
  process.exitCode = originalExitCode;
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

for (const entry of cases) {
  const run = async (origin = 'http://127.0.0.1:12345') => {
    const command = entry.module === 'authorize-current'
      ? (await import('../src/commands/authorize-current.js')).authorizeCurrentCommand
      : entry.module === 'inspect-current'
        ? (await import('../src/commands/inspect-current.js')).inspectCurrentCommand
        : (await import('../src/commands/observation.js')).observationCommand;
    await command.parseAsync([...entry.args, '--api-url', origin], { from: 'user' });
  };
  describe(entry.name, () => {
    it('forwards exact stdin and bearer token and prints the returned report', async () => {
      await run();
      expect(readInput).toHaveBeenCalledExactlyOnceWith(process.stdin);
      expect(clients[entry.client]).toHaveBeenCalledExactlyOnceWith('http://127.0.0.1:12345', 'synthetic-token', bytes);
      expect(output).toHaveBeenCalledExactlyOnceWith('{"cryptographic_valid":true}\n');
      expect(errors).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(0);
    });
    it('rejects an unsafe origin before reading private input or sending a request', async () => {
      await run('http://external.example');
      expect(readInput).not.toHaveBeenCalled();
      expect(clients[entry.client]).not.toHaveBeenCalled();
      expect(output).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
    });
    it('rejects missing credentials before reading private input', async () => {
      vi.stubEnv('CLEARPROOF_API_TOKEN', undefined);
      await run();
      expect(readInput).not.toHaveBeenCalled();
      expect(clients[entry.client]).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
    });
    it('sanitizes failed API responses and does not print a success report', async () => {
      clients[entry.client].mockRejectedValueOnce(new Error('SYNTHETIC-PRIVATE-ERROR'));
      await run();
      expect(output).not.toHaveBeenCalled();
      expect(errors).toHaveBeenCalledOnce();
      expect(errors.mock.calls.flat().join('')).not.toContain('SYNTHETIC-PRIVATE-ERROR');
      expect(process.exitCode).toBe(2);
      if (entry.name === 'authorize-current') {
        expect(errors.mock.calls.flat().join('')).toContain('same request and idempotency key');
      }
    });
    it('does not submit a request when reading stdin fails', async () => {
      readInput.mockRejectedValueOnce(new Error('stdin unavailable'));
      await run();
      expect(clients[entry.client]).not.toHaveBeenCalled();
      expect(output).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(2);
    });
    it('distinguishes a negative inspection from transport failure', async () => {
      clients[entry.client].mockResolvedValueOnce({ cryptographic_valid: false });
      await run();
      expect(output).toHaveBeenCalledExactlyOnceWith('{"cryptographic_valid":false}\n');
      expect(errors).not.toHaveBeenCalled();
      expect(process.exitCode).toBe(entry.name === 'inspect-current' ? 1 : 0);
    });
  });
}
