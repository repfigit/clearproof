/** BN254 scalar field helpers shared by every public-signal boundary in this SDK. */

/** Order of the BN254 scalar field. Every Groth16 public signal must be strictly below it. */
export const SCALAR_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * True for a canonical decimal string (no sign, no leading zeros, no whitespace)
 * that encodes an element of the BN254 scalar field. Safe to pass to BigInt().
 */
export function isFieldElementString(value: unknown): value is string {
  return typeof value === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(value) && BigInt(value) < SCALAR_FIELD_MODULUS;
}

/** True when `value` is an array of canonical field-element strings, optionally of an exact length. */
export function isFieldElementArray(value: unknown, length?: number): value is string[] {
  return Array.isArray(value) && (length === undefined || value.length === length) &&
    value.every(isFieldElementString);
}
