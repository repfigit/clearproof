import { canonicalBytes } from './canonical.js';

export interface WalletOwnershipCredential {
  schema_version: 'clearproof-credential-v1';
  tenant_id: string;
  credential_nonce: string;
  issuer_did: string;
  subject_wallet: string;
  holder_commitment: string;
  jurisdiction: string;
  kyc_tier: number;
  sanctions_clear: boolean;
  issued_at: number;
  expires_at: number;
}

export interface WalletOwnershipChallenge {
  schema_version: 'clearproof-wallet-challenge-v1';
  tenant_id: string;
  actor_id: string;
  credential: WalletOwnershipCredential;
  chain_id: number;
  registry_address: string;
  nonce: string;
  timestamp: number;
  expires_at: number;
}

export interface ExpectedWalletOwnershipContext {
  tenantId: string;
  actorId: string;
  credential: WalletOwnershipCredential;
  chainId: number;
  registryAddress: string;
}

/**
 * Validate the challenge against independently retained enrollment context and
 * return exact EIP-191 personal_sign text. Never pass context copied from the
 * challenge as `expected`. Signing does not establish current proof eligibility.
 */
export function walletOwnershipSigningMessage(
  challenge: WalletOwnershipChallenge,
  expected: ExpectedWalletOwnershipContext,
  now = Math.floor(Date.now() / 1000),
): string {
  const encoded = canonicalBytes(challenge);
  const keys = ['schema_version', 'tenant_id', 'actor_id', 'credential', 'chain_id',
    'registry_address', 'nonce', 'timestamp', 'expires_at'];
  if (Object.keys(challenge).length !== keys.length || keys.some(key => !Object.hasOwn(challenge, key)) ||
      challenge.schema_version !== 'clearproof-wallet-challenge-v1' ||
      challenge.credential.schema_version !== 'clearproof-credential-v1' ||
      challenge.tenant_id !== expected.tenantId || challenge.actor_id !== expected.actorId ||
      challenge.chain_id !== expected.chainId || challenge.registry_address !== expected.registryAddress ||
      challenge.credential.tenant_id !== expected.tenantId ||
      !canonicalBytes(challenge.credential).equals(canonicalBytes(expected.credential)) ||
      !/^[0-9a-f]{64}$/.test(challenge.nonce) || /^0+$/.test(challenge.nonce) ||
      !/^0x[0-9a-f]{40}$/.test(challenge.registry_address) || /^0x0+$/.test(challenge.registry_address) ||
      !Number.isSafeInteger(challenge.chain_id) || challenge.chain_id < 1 ||
      ![now, challenge.timestamp, challenge.expires_at].every(n => Number.isSafeInteger(n) && n >= 0) ||
      challenge.expires_at !== challenge.timestamp + 300 ||
      now < challenge.timestamp || now >= challenge.expires_at ||
      now < expected.credential.issued_at || now >= expected.credential.expires_at) {
    throw new Error('Wallet challenge context or validity failed');
  }
  return 'Clearproof wallet ownership verification v1\n' + encoded.toString('utf8');
}
