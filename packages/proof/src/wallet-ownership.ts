import { canonicalBytes } from './canonical.js';
import { toChecksumAddress } from './eip55.js';

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

// SIWE (ERC-4361) profile: the challenge message itself is the
// supervisor-readable record (domain, nonce, chain-id, issued-at,
// expiration-time). The fixture type is structurally identical to the server's
// clearproof-wallet-challenge-v2 record.
export interface WalletOwnershipChallengeV2 {
  schema_version: 'clearproof-wallet-challenge-v2';
  tenant_id: string;
  actor_id: string;
  credential: WalletOwnershipCredential;
  chain_id: number;
  registry_address: string;
  nonce: string;
  timestamp: number;
  expires_at: number;
  siwe_domain: string;
  siwe_resource: string;
}

export type AnyWalletOwnershipChallenge = WalletOwnershipChallenge | WalletOwnershipChallengeV2;

export interface ExpectedWalletOwnershipContext {
  tenantId: string;
  actorId: string;
  credential: WalletOwnershipCredential;
  chainId: number;
  registryAddress: string;
}

export const WALLET_OWNERSHIP_SIWE_STATEMENT =
  'Sign to verify control of this wallet for an EU TFR wallet-ownership attestation (Clearproof).';

/** Render a Unix epoch as the ISO-8601 instant the server emits (UTC, Z suffix). */
export function isoEpoch(epoch: number): string {
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new Error('Invalid SIWE timestamp');
  }
  return new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Render the deterministic EIP-4361 message for a v2 challenge. Field order and
 * blank-line placement mirror the server's Python renderer byte for byte; the
 * shared test vector (tests/vectors/wallet-ownership/challenge-v2.json) proves
 * the parity. Never populate the expected context from the challenge itself.
 */
export function siweWalletOwnershipMessage(challenge: WalletOwnershipChallengeV2): string {
  const { siwe_domain: domain, credential, chain_id: chainId, nonce, timestamp, expires_at: expiresAt } = challenge;
  return (
    `${domain} wants you to sign in with your Ethereum account:\n` +
    `${toChecksumAddress(credential.subject_wallet)}\n` +
    '\n' +
    `${WALLET_OWNERSHIP_SIWE_STATEMENT}\n` +
    '\n' +
    `URI: https://${domain}/wallet/ownership\n` +
    'Version: 1\n' +
    `Chain ID: ${chainId}\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${isoEpoch(timestamp)}\n` +
    `Expiration Time: ${isoEpoch(expiresAt)}\n` +
    'Resources:\n' +
    `- ${challenge.siwe_resource}`
  );
}

function validateSharedContext(
  challenge: AnyWalletOwnershipChallenge,
  expected: ExpectedWalletOwnershipContext,
  now: number,
): void {
  const keys = ['schema_version', 'tenant_id', 'actor_id', 'credential', 'chain_id',
    'registry_address', 'nonce', 'timestamp', 'expires_at'];
  const v2 = challenge.schema_version === 'clearproof-wallet-challenge-v2';
  if (Object.keys(challenge).length !== keys.length + (v2 ? 2 : 0) ||
      keys.some(key => !Object.hasOwn(challenge, key)) ||
      (challenge.schema_version !== 'clearproof-wallet-challenge-v1' &&
        challenge.schema_version !== 'clearproof-wallet-challenge-v2') ||
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
      now + 30 < challenge.timestamp || now - 30 >= challenge.expires_at ||
      now + 30 < expected.credential.issued_at || now - 30 >= expected.credential.expires_at) {
    throw new Error('Wallet challenge context or validity failed');
  }
  if (v2) {
    const { siwe_domain: domain, siwe_resource: resource } = challenge as WalletOwnershipChallengeV2;
    if (typeof domain !== 'string' || domain.length === 0 || domain.length > 253 ||
        domain.includes('\n') || domain !== domain.trim() ||
        typeof resource !== 'string' || resource.length === 0 || resource.length > 512 ||
        resource.includes('\n')) {
      throw new Error('Wallet challenge context or validity failed');
    }
  }
}

/**
 * Validate the challenge against independently retained enrollment context and
 * return the exact signing text: the EIP-4361 (SIWE) message for v2 challenges,
 * or the legacy canonical v1 text. A 30-second client clock tolerance only
 * affects message preparation; the server enforces exact validity. Never pass
 * context copied from the challenge as `expected`. Signing does not establish
 * current proof eligibility.
 */
export function walletOwnershipSigningMessage(
  challenge: AnyWalletOwnershipChallenge,
  expected: ExpectedWalletOwnershipContext,
  now = Math.floor(Date.now() / 1000),
): string {
  validateSharedContext(challenge, expected, now);
  if (challenge.schema_version === 'clearproof-wallet-challenge-v2') {
    return siweWalletOwnershipMessage(challenge);
  }
  return 'Clearproof wallet ownership verification v1\n' + canonicalBytes(challenge).toString('utf8');
}
