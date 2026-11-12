import { beforeEach, expect, test, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ getContractFactory: vi.fn(), id: vi.fn(), provider: { getNetwork: vi.fn() } }));
vi.mock('hardhat', () => ({ ethers: mocks }));
import { assertDevelopmentKeyChain, prepareLegacyVerifier } from '../../packages/contracts/scripts/legacy-verifier';

beforeEach(() => {
  vi.resetAllMocks();
  mocks.provider.getNetwork.mockResolvedValue({ chainId: 31337n });
});

test.each([1n, 8453n, 42161n, 137n, 10n, 999999n])(
  'refuses chain %s before deploying: the verifier embeds development-only keys', async chainId => {
    mocks.provider.getNetwork.mockResolvedValue({ chainId });
    await expect(prepareLegacyVerifier()).rejects.toThrow(`Refusing to deploy the legacy verifier to chain ${chainId}`);
    expect(mocks.getContractFactory).not.toHaveBeenCalled();
  },
);

test.each([31337n, 11155111n, 84532n, 421614n, 80002n, 11155420n])('allows local or testnet chain %s', async chainId => {
  mocks.provider.getNetwork.mockResolvedValue({ chainId });
  await expect(assertDevelopmentKeyChain()).resolves.toBeUndefined();
});

test.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
  'rejects invalid activation delay %s before deploying', async delay => {
    await expect(prepareLegacyVerifier(delay)).rejects.toThrow('Invalid verifier timelock');
    expect(mocks.getContractFactory).not.toHaveBeenCalled();
  },
);

test.each([undefined, 3600])('registers the verifier with a pending timelock for delay %s', async delay => {
  const transactionWait = vi.fn().mockResolvedValue(undefined);
  const router = {
    waitForDeployment: vi.fn().mockResolvedValue(undefined),
    registerVerifier: vi.fn().mockResolvedValue({ wait: transactionWait }),
    timelocks: vi.fn().mockResolvedValue(12345678901234567890n),
  };
  const verifier = {
    waitForDeployment: vi.fn().mockResolvedValue(undefined),
    getAddress: vi.fn().mockResolvedValue('0x0000000000000000000000000000000000000001'),
  };
  const deployRouter = vi.fn().mockResolvedValue(router);
  const deployVerifier = vi.fn().mockResolvedValue(verifier);
  mocks.getContractFactory.mockImplementation(async name => {
    if (name === 'VerifierRouter') return { deploy: deployRouter };
    if (name === 'Groth16Verifier') return { deploy: deployVerifier };
    throw new Error(`Unexpected contract ${name}`);
  });
  mocks.id.mockReturnValue('selector');
  const result = await prepareLegacyVerifier(delay);
  expect(deployRouter).toHaveBeenCalledWith(delay ?? 86400);
  expect(deployVerifier).toHaveBeenCalledWith();
  expect(router.waitForDeployment).toHaveBeenCalledOnce();
  expect(verifier.waitForDeployment).toHaveBeenCalledOnce();
  expect(mocks.id).toHaveBeenCalledWith('groth16-bn254-v1');
  expect(router.registerVerifier).toHaveBeenCalledWith(
    'selector', '0x0000000000000000000000000000000000000001', 'Legacy Groth16 BN254 v1',
  );
  expect(transactionWait).toHaveBeenCalledOnce();
  expect(router.timelocks).toHaveBeenCalledWith('selector');
  expect(result).toEqual({ router, verifier, selector: 'selector', timelockPeriod: delay ?? 86400,
    activation: { status: 'pending-timelock', selector: 'selector', name: 'Legacy Groth16 BN254 v1',
      activateAfter: '12345678901234567890' } });
});
