/**
 * Jurisdiction -> amount-tier thresholds.
 *
 * These values are a consensus parameter, not a local preference: the circuit
 * takes tier2/3/4_threshold as *unconstrained* public inputs (signals 8-10),
 * so the prover chooses them. Security comes from every verifier checking the
 * submitted thresholds against this table. If this table disagrees with the
 * Python SDK or the on-chain ComplianceRegistry, proofs will verify in one
 * place and fail in another.
 *
 * Source of truth: config/jurisdiction_thresholds.json (asserted by
 * test/thresholds.test.ts).
 */

export interface Thresholds {
  tier2: number;
  tier3: number;
  tier4: number;
}

export const JURISDICTION_THRESHOLDS: Readonly<Record<string, Thresholds>> = Object.freeze({
  US: { tier2: 250, tier3: 3000, tier4: 10000 },
  EU: { tier2: 250, tier3: 1000, tier4: 10000 },
  SG: { tier2: 250, tier3: 1500, tier4: 10000 },
  AE: { tier2: 250, tier3: 1000, tier4: 10000 },
});

/** FATF $1,000 global threshold, applied to jurisdictions without an explicit entry. */
export const DEFAULT_THRESHOLDS: Readonly<Thresholds> = Object.freeze({
  tier2: 250,
  tier3: 1000,
  tier4: 10000,
});

/**
 * Decode `jurisdiction_code` (public signal 6) back to its ISO 3166-1 alpha-2
 * form. The circuit carries the code as the big-endian ASCII value of the two
 * letters, e.g. "US" -> 0x5553 -> 21843.
 *
 * Returns null if the value is not two uppercase ASCII letters.
 */
export function decodeJurisdiction(code: string | number | bigint): string | null {
  let value: bigint;
  try {
    value = BigInt(code);
  } catch {
    return null;
  }
  if (value < 0n || value > 0xffffn) return null;

  const hi = Number((value >> 8n) & 0xffn);
  const lo = Number(value & 0xffn);
  const isUpper = (c: number) => c >= 0x41 && c <= 0x5a;
  if (!isUpper(hi) || !isUpper(lo)) return null;

  return String.fromCharCode(hi, lo);
}

/** Thresholds for a jurisdiction, falling back to the FATF default. */
export function getThresholds(jurisdiction: string): Thresholds {
  return JURISDICTION_THRESHOLDS[jurisdiction.toUpperCase()] ?? DEFAULT_THRESHOLDS;
}

/**
 * Check if the jurisdiction code in the public signals matches an expected jurisdiction.
 *
 * @param publicSignals The full 16-element array of public signals
 * @param expectedJurisdiction The expected jurisdiction code (e.g. "US", "EU")
 * @returns true if the jurisdiction codes match, false otherwise
 */
export function jurisdictionMatchesVASP(publicSignals: string[], expectedJurisdiction: string): boolean {
  if (publicSignals.length < 16) return false;

  const claimedJurisdiction = decodeJurisdiction(publicSignals[6]);
  if (claimedJurisdiction === null) return false;

  return claimedJurisdiction === expectedJurisdiction.toUpperCase();
}

/**
 * Check that the thresholds carried in the public signals are the ones this
 * verifier expects for the jurisdiction the proof claims.
 *
 * `publicSignals` must be the full 16-element array.
 */
export function thresholdsMatchJurisdiction(publicSignals: string[]): boolean {
  if (publicSignals.length < 16) return false;

  const jurisdiction = decodeJurisdiction(publicSignals[6]);
  if (jurisdiction === null) return false;

  const expected = getThresholds(jurisdiction);
  return (
    BigInt(publicSignals[8]) === BigInt(expected.tier2) &&
    BigInt(publicSignals[9]) === BigInt(expected.tier3) &&
    BigInt(publicSignals[10]) === BigInt(expected.tier4)
  );
}
