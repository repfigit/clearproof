import fs from 'fs';
import path from 'path';
import { describe, expect, it } from 'vitest';

const contentRoot = path.resolve(__dirname, '../content');

function readRecipe(name: string): string {
  return fs.readFileSync(path.join(contentRoot, 'recipes', `${name}.md`), 'utf-8');
}

describe('developer recipes', () => {
  it('include API-key auth on protected API calls', () => {
    for (const recipe of ['generate-proof', 'full-walkthrough', 'verify-proof']) {
      const markdown = readRecipe(recipe);
      const protectedCalls = markdown.match(/curl -s -X POST http:\/\/localhost:8000\/(?:credential|proof)\/[^\s]+/g) ?? [];

      expect(protectedCalls.length, `${recipe} should exercise protected endpoints`).toBeGreaterThan(0);
      expect(markdown, `${recipe} should define CLEARPROOF_API_KEY`).toContain('CLEARPROOF_API_KEY');
      expect(markdown, `${recipe} should send X-API-Key`).toContain('-H "X-API-Key: $CLEARPROOF_API_KEY"');
    }
  });

  it('documents environment required by on-chain scripts', () => {
    const markdown = readRecipe('verify-onchain');

    expect(markdown).toContain('DEPLOYER_PRIVATE_KEY');
    expect(markdown).toContain('PROOF_PATH');
    expect(markdown).toContain('TRANSFER_ID');
    expect(markdown).toContain('VASP_DID');
    expect(markdown).toContain('scripts/verify-onchain.ts');
    expect(markdown).toContain('scripts/check-transfer.ts');
  });
});
