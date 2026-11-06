import { keccak256 } from 'js-sha3';

/**
 * EIP-55 mixed-case checksum encoding of a 20-byte hex address.
 *
 * SIWE (EIP-4361) messages must carry the checksummed form of the subject
 * address, while the rest of the protocol keeps lowercase hex internally.
 * keccak256 over the lowercase hex string (without the 0x prefix); each hex
 * letter is uppercased when the corresponding hash nibble is >= 8.
 */
export function toChecksumAddress(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error('Invalid Ethereum address');
  }
  const lower = address.toLowerCase();
  const hash = keccak256(lower.slice(2));
  let checksummed = '0x';
  for (let i = 0; i < 40; i++) {
    const nibble = parseInt(hash[i], 16);
    const character = lower[2 + i];
    checksummed += nibble >= 8 ? character.toUpperCase() : character;
  }
  return checksummed;
}
