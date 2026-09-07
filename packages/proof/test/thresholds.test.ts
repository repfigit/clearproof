import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  JURISDICTION_THRESHOLDS,
  DEFAULT_THRESHOLDS,
  decodeJurisdiction,
  getThresholds,
  thresholdsMatchJurisdiction,
} from '../src/thresholds.js';

/**
 * AIF-79 — threshold binding.
 *
 * tier2/3/4_threshold (signals 8-10) are unconstrained public inputs, so the
 * prover chooses them. Every verifier must re-derive them from the same table.
 */

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const config = JSON.parse(
  readFileSync(resolve(REPO_ROOT, 'config/jurisdiction_thresholds.json'), 'utf-8'),
);

function signals(jurisdiction = 'US', tier2 = 250, tier3 = 3000, tier4 = 10000): string[] {
  const s = Array(16).fill('0');
  const buf = Buffer.from(jurisdiction, 'ascii');
  s[6] = String((buf[0] << 8) | buf[1]);
  s[8] = String(tier2);
  s[9] = String(tier3);
  s[10] = String(tier4);
  return s;
}

describe('decodeJurisdiction', () => {
  it('decodes big-endian ASCII', () => {
    expect(decodeJurisdiction('21843')).toBe('US'); // 0x5553
    expect(decodeJurisdiction(0x4555)).toBe('EU');
  });

  it('rejects values that are not two uppercase letters', () => {
    for (const bad of [-1, 0, 0x3031, 0x10000, 0x4160, 0x2020]) {
      expect(decodeJurisdiction(bad)).toBeNull();
    }
  });

  it('rejects unparseable input', () => {
    expect(decodeJurisdiction('not-a-number')).toBeNull();
  });
});

describe('thresholdsMatchJurisdiction', () => {
  it('accepts correct thresholds', () => {
    expect(thresholdsMatchJurisdiction(signals('US', 250, 3000, 10000))).toBe(true);
  });

  it('rejects the tier-1 attack', () => {
    // Arbitrarily high tier2 lands any amount in tier 1, defeating the tier
    // attestation and the SAR review flag.
    expect(thresholdsMatchJurisdiction(signals('US', 2 ** 63, 3000, 10000))).toBe(false);
  });

  it('rejects thresholds borrowed from another jurisdiction', () => {
    expect(thresholdsMatchJurisdiction(signals('US', 250, 1000, 10000))).toBe(false);
  });

  it('rejects a malformed jurisdiction code', () => {
    const s = signals('US');
    s[6] = '12345678';
    expect(thresholdsMatchJurisdiction(s)).toBe(false);
  });

  it('rejects a short signal array', () => {
    expect(thresholdsMatchJurisdiction(Array(15).fill('0'))).toBe(false);
  });

  it('resolves unregistered jurisdictions through the default table', () => {
    const d = DEFAULT_THRESHOLDS;
    expect(thresholdsMatchJurisdiction(signals('GB', d.tier2, d.tier3, d.tier4))).toBe(true);
    expect(thresholdsMatchJurisdiction(signals('GB', 250, 3000, 10000))).toBe(false);
  });
});

describe('cross-language parity', () => {
  it('matches the canonical config', () => {
    for (const [code, expected] of Object.entries(config.jurisdictions)) {
      expect(getThresholds(code), `TypeScript disagrees with config for ${code}`).toEqual(expected);
    }
    expect(DEFAULT_THRESHOLDS).toEqual(config.default);
  });

  it('has no extra jurisdictions', () => {
    expect(Object.keys(JURISDICTION_THRESHOLDS).sort()).toEqual(
      Object.keys(config.jurisdictions).sort(),
    );
  });

  it('keeps thresholds strictly ordered', () => {
    // Mirrors the ThresholdsNotOrdered guard in setJurisdictionThresholds.
    for (const t of [...Object.values(JURISDICTION_THRESHOLDS), DEFAULT_THRESHOLDS]) {
      expect(t.tier2).toBeLessThan(t.tier3);
      expect(t.tier3).toBeLessThan(t.tier4);
    }
  });

  it('default is at least as strict as every registered jurisdiction', () => {
    /**
     * AIF-97 — the default thresholds are the fail-to-strictest fallback for
     * unregistered jurisdiction codes. A lower tier escalates to Travel Rule
     * sooner, so `default.tierN <= jurisdiction.tierN` for every tier means
     * the prover cannot profit from claiming an unknown code: the fallback
     * is never looser than a registered jurisdiction.
     *
     * If a new jurisdiction is added with a stricter threshold than the
     * default, this test fails and the default must be reviewed and lowered
     * to maintain the invariant; do not weaken a jurisdiction's policy
     * merely to satisfy this test.
     */
    for (const [code, thresholds] of Object.entries(config.jurisdictions) as [string, { tier2: number; tier3: number; tier4: number }][]) {
      expect(DEFAULT_THRESHOLDS.tier2, `${code} tier2 stricter than default`).toBeLessThanOrEqual(thresholds.tier2);
      expect(DEFAULT_THRESHOLDS.tier3, `${code} tier3 stricter than default`).toBeLessThanOrEqual(thresholds.tier3);
      expect(DEFAULT_THRESHOLDS.tier4, `${code} tier4 stricter than default`).toBeLessThanOrEqual(thresholds.tier4);
    }
  });
});
