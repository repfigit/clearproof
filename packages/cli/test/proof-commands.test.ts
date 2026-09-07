import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

const clients = vi.hoisted(() => ({ generateProof: vi.fn(), verifyProof: vi.fn() }));
vi.mock('@clearproof/proof', async importOriginal => ({
  ...await importOriginal<typeof import('@clearproof/proof')>(), ...clients,
}));
let directory: string;
let output: ReturnType<typeof vi.spyOn>;
let errors: ReturnType<typeof vi.spyOn>;
let exit: ReturnType<typeof vi.spyOn>;
const originalExitCode = process.exitCode;
const input = {
  sanctionsTreeRoot: '101', issuerTreeRoot: '102', amountTier: 2,
  transferTimestamp: 1000, jurisdictionCode: 21843, credentialCommitment: '103',
  tier2Threshold: 25000, tier3Threshold: 300000, tier4Threshold: 1000000,
  domainChainId: 31337, domainContractHash: '104', transferIdHash: '105',
  credentialNullifier: '106', proofExpiresAt: 1300, issuerDid: '107',
  kycTier: 3, sanctionsClear: 1, issuedAt: 900, expiresAt: 2000,
  issuerPathElements: ['108'], issuerPathIndices: ['0'], walletAddressHash: '109',
  leftKey: '110', rightKey: '112', leftPathElements: ['113'], leftPathIndices: ['1'],
  rightPathElements: ['114'], rightPathIndices: ['0'], actualAmount: 12345,
};
const generated = { proof: { pi_a: ['1', '2', '1'] }, publicSignals: ['1', '0'], proofTime: 123 };

beforeEach(() => {
  vi.resetModules();
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'clearproof-cli-proof-test-'));
  // These placeholders exercise CLI file selection only. The SDK is mocked;
  // actual circuit/proving-key tests run separately with development artifacts.
  for (const name of ['compliance.wasm', 'compliance_final.zkey', 'verification_key.json']) {
    fs.writeFileSync(path.join(directory, name), `synthetic ${name}`);
  }
  fs.writeFileSync(path.join(directory, 'input.json'), JSON.stringify(input));
  fs.writeFileSync(path.join(directory, 'proof.json'), JSON.stringify(generated));
  clients.generateProof.mockReset().mockResolvedValue(generated);
  clients.verifyProof.mockReset();
  output = vi.spyOn(console, 'log').mockImplementation(() => {});
  errors = vi.spyOn(console, 'error').mockImplementation(() => {});
  exit = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('synthetic exit'); });
  process.exitCode = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = originalExitCode;
  fs.rmSync(directory, { recursive: true, force: true });
});
async function prove(extra: string[] = []) {
  const { proveCommand } = await import('../src/commands/prove.js');
  await proveCommand.parseAsync(['--input', path.join(directory, 'input.json'), '--artifacts', directory, ...extra], { from: 'user' });
}

describe('proof CLI file and SDK boundary', () => {
  it('selects explicit artifact paths and writes proof JSON to stdout', async () => {
    await prove();
    expect(clients.generateProof).toHaveBeenCalledExactlyOnceWith(input,
      path.join(directory, 'compliance.wasm'), path.join(directory, 'compliance_final.zkey'));
    expect(JSON.parse(output.mock.calls[0][0] as string)).toEqual(generated);
    expect(errors.mock.calls.flat().join('\n')).toContain('123 ms');
  });
  it('writes to the selected output file without duplicating JSON on stdout', async () => {
    const destination = path.join(directory, 'result.json');
    await prove(['--output', destination]);
    expect(JSON.parse(fs.readFileSync(destination, 'utf8'))).toEqual(generated);
    expect(output).not.toHaveBeenCalled();
    expect(errors.mock.calls.flat().join('\n')).toContain(`Written to ${destination}`);
  });
  it('fails before proving when an artifact is missing', async () => {
    fs.unlinkSync(path.join(directory, 'compliance_final.zkey'));
    await prove();
    expect(clients.generateProof).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    expect(output).not.toHaveBeenCalled();
  });
  it('propagates malformed input without invoking the SDK', async () => {
    fs.writeFileSync(path.join(directory, 'input.json'), '{');
    await expect(prove()).rejects.toBeInstanceOf(SyntaxError);
    expect(clients.generateProof).not.toHaveBeenCalled();
  });
  it('does not write a successful proof after SDK rejection', async () => {
    clients.generateProof.mockRejectedValueOnce(new Error('constraint rejected'));
    const destination = path.join(directory, 'result.json');
    await expect(prove(['--output', destination])).rejects.toThrow('constraint rejected');
    expect(fs.existsSync(destination)).toBe(false);
    expect(output).not.toHaveBeenCalled();
  });
  it.each([true, false])('prints verifier result %s and sets the matching exit status', async valid => {
    const result = { valid, isCompliant: valid, sarReviewFlag: !valid, publicSignals: generated.publicSignals };
    clients.verifyProof.mockResolvedValueOnce(result);
    const { verifyCommand } = await import('../src/commands/verify.js');
    await expect(verifyCommand.parseAsync(['--proof', path.join(directory, 'proof.json'), '--artifacts', directory],
      { from: 'user' })).rejects.toThrow('synthetic exit');
    expect(clients.verifyProof).toHaveBeenCalledExactlyOnceWith(generated.proof, generated.publicSignals,
      path.join(directory, 'verification_key.json'));
    expect(JSON.parse(output.mock.calls[0][0] as string)).toEqual(result);
    expect(exit).toHaveBeenCalledExactlyOnceWith(valid ? 0 : 1);
  });
});


describe('development demo CLI', () => {
  async function demo(extra: string[] = []) {
    const { demoCommand } = await import('../src/commands/demo.js');
    return demoCommand.parseAsync(['--artifacts', directory, ...extra], { from: 'user' });
  }
  it('exports only development-labelled vectors with hashes of the selected artifacts', async () => {
    clients.verifyProof.mockResolvedValue({ valid: true, isCompliant: true, sarReviewFlag: false });
    const destination = path.join(directory, 'export');
    await expect(demo(['--export', destination])).rejects.toThrow('synthetic exit');
    const load = (name: string) => JSON.parse(fs.readFileSync(path.join(destination, name), 'utf8'));
    expect(load('proof.json')).toEqual(generated.proof);
    expect(load('public.json')).toEqual(generated.publicSignals);
    expect(load('input.json')).toEqual(clients.generateProof.mock.calls[0][0]);
    expect(fs.readFileSync(path.join(destination, 'verification_key.json'), 'utf8'))
      .toBe('synthetic verification_key.json');
    const manifest = load('MANIFEST.json');
    expect(manifest.devKeysOnly).toBe(true);
    expect(manifest.warning).toContain('NOT valid for production');
    expect(manifest.artifacts).toEqual(Object.fromEntries([
      ['wasm_sha256', 'compliance.wasm'], ['zkey_sha256', 'compliance_final.zkey'],
      ['vkey_sha256', 'verification_key.json'],
    ].map(([key, name]) => [key, createHash('sha256').update(`synthetic ${name}`).digest('hex')])));
    expect(exit).toHaveBeenCalledExactlyOnceWith(0);
  });
  it('prints a failed result and exits unsuccessfully for unexpected public signals', async () => {
    clients.generateProof.mockResolvedValue({ ...generated, publicSignals: Array(17).fill('0') });
    clients.verifyProof.mockResolvedValue({ valid: false, isCompliant: false, sarReviewFlag: false });
    await expect(demo()).rejects.toThrow('synthetic exit');
    expect(output.mock.calls.flat().join('\n')).toContain('signal_16: 0');
    expect(output.mock.calls.flat().join('\n')).toContain('proof FAILED');
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });
  it('rejects absent artifacts without invoking the SDK', async () => {
    fs.unlinkSync(path.join(directory, 'compliance.wasm'));
    await demo();
    expect(process.exitCode).toBe(2);
    expect(clients.generateProof).not.toHaveBeenCalled();
  });
});
